import atexit
import logging
import sys  # 新增导入
from concurrent.futures import ThreadPoolExecutor
from flask import render_template, redirect, Flask
from flask import request, abort, jsonify
from langchain.storage import redis
import services.llm_service as llm_service_module
import hook.push_process
import hook.routes_detailed
import hook.routes_general
from config.core_config import gitlab_project_configs, remove_processed_commit_entries_for_pr_mr, \
    is_commit_processed, github_repo_configs, SERVER_HOST, SERVER_PORT, init_redis_client, app_configs, \
    load_configs_from_redis, ADMIN_API_KEY
from services.llm_service import initialize_openai_client
from services.vcs_service import get_gitlab_mr_changes
from config.utils import verify_github_signature, verify_gitlab_signature
from hook.helpers import handle_async_task_exception
from config.config_routes import app as config_app

# NOTE: config.core_config loads .env at import time so module-level settings like
# ADMIN_API_KEY are correct even when core_config is imported indirectly (e.g., via
# services.*) before this file runs.
app = Flask(__name__, template_folder='web/templates', static_folder='web/static')
# 注册配置相关的路由
app.register_blueprint(config_app)

executor = ThreadPoolExecutor(max_workers=20)  # 您可以根据需要调整 max_workers

@app.route('/review_results')
def review_results_page():
    """提供AI审查记录查看页面的 HTML 页面"""
    return render_template('review_results.html')


@app.route('/')
def index():
    # Keep backward compatibility for the old entry point.
    return redirect('/admin')


@app.route('/admin')
def admin_page():
    return render_template('admin.html')


@app.route('/gitlab_webhook', methods=['POST'])
def gitlab_webhook():
    """处理 GitLab Webhook 请求"""
    try:
        data = request.get_json()
        if data is None: raise ValueError("请求体为空或非有效 JSON")
    except Exception as e:
        logger.error(f"解析 GitLab JSON 负载时出错: {e}")
        abort(400, "无效的 JSON 负载")

    project_data = data.get('project', {})
    project_id = project_data.get('id')
    project_web_url = project_data.get('web_url')
    project_name_from_payload = project_data.get('name')
    mr_attrs = data.get('object_attributes', {})
    mr_iid = mr_attrs.get('iid')
    mr_title = mr_attrs.get('title')
    mr_url = mr_attrs.get('url')
    last_commit = mr_attrs.get('last_commit', {})
    head_sha_payload = last_commit.get('id')

    if not project_id or not mr_iid:
        logger.error("错误: GitLab 负载中缺少 project_id 或 mr_iid。")
        abort(400, "GitLab 负载中缺少 project_id 或 mr_iid")

    project_id_str = str(project_id)
    config = gitlab_project_configs.get(project_id_str)
    if not config:
        logger.error(f"错误: 未找到 GitLab 项目 ID {project_id_str} 的配置。")
        abort(404, f"未找到 GitLab 项目 {project_id_str} 的配置。请通过 /config/gitlab/project 端点进行配置。")

    webhook_secret = config.get('secret')
    access_token = config.get('token')

    if not verify_gitlab_signature(request, webhook_secret):
        abort(401, "GitLab signature verification failed.")

    event_type = request.headers.get('X-Gitlab-Event')
    if event_type == "Push Hook":
        logger.info("GitLab: 收到 Push Hook 事件，转发到 /gitlab_push_webhook 处理。")
        from hook.push_process import gitlab_push_webhook
        return gitlab_push_webhook()
    if event_type != "Merge Request Hook":
        logger.info(f"GitLab: 忽略事件类型: {event_type}")
        return "事件已忽略", 200

    mr_action = mr_attrs.get('action')
    mr_state = mr_attrs.get('state')

    if mr_action in ['close', 'merge'] or mr_state in ['closed', 'merged']:
        mr_iid_str = str(mr_iid)
        logger.info(
            f"GitLab: MR {project_id_str}#{mr_iid_str} 已 {mr_action if mr_action in ['close', 'merge'] else mr_state}。正在清理 Redis 记录...")
        remove_processed_commit_entries_for_pr_mr('gitlab', project_id_str, mr_iid_str)
        return f"MR {mr_iid_str} 已 {mr_action if mr_action in ['close', 'merge'] else mr_state}，记录已清理。", 200

    if mr_state not in ['opened', 'reopened'] and mr_action != 'update':
        logger.info(f"GitLab: 忽略 MR 操作 '{mr_action}' 或状态 '{mr_state}' (非审查触发条件)。")
        return "MR 操作/状态已忽略 (非审查触发条件)", 200

    logger.info(f"--- 收到 GitLab Merge Request Hook (详细审查) ---")
    logger.info(f"项目 ID: {project_id_str}, MR IID: {mr_iid}, Head SHA (来自负载): {head_sha_payload}")

    if head_sha_payload and is_commit_processed('gitlab', project_id_str, str(mr_iid), head_sha_payload):
        logger.info(f"GitLab (详细审查): MR {project_id_str}#{mr_iid} 的提交 {head_sha_payload} 已处理。跳过。")
        return "提交已处理", 200

    # 调用提取出来的核心处理逻辑函数 (异步执行)
    future = executor.submit(hook.routes_detailed._process_gitlab_detailed_payload, access_token=access_token,
                             project_id_str=project_id_str, mr_iid=mr_iid, head_sha_payload=head_sha_payload,
                             project_data=project_data, mr_attrs=mr_attrs, project_web_url=project_web_url,
                             mr_title=mr_title, mr_url=mr_url, project_name_from_payload=project_name_from_payload)
    future.add_done_callback(handle_async_task_exception)

    logger.info(f"GitLab (详细审查): MR {project_id_str}#{mr_iid} 的处理任务已提交到后台执行。")
    return jsonify({"message": "GitLab Detailed Webhook processing task accepted."}), 202


@app.route('/github_webhook', methods=['POST'])
def github_webhook():
    """处理 GitHub Webhook 请求"""
    try:
        payload_data = request.get_json()
        if payload_data is None: raise ValueError("请求体为空或非有效 JSON")
    except Exception as e:
        logger.error(f"解析 GitHub JSON 负载时出错: {e}")
        abort(400, "无效的 JSON 负载")

    repo_info = payload_data.get('repository', {})
    repo_full_name = repo_info.get('full_name')

    if not repo_full_name:
        logger.error("错误: GitHub 负载中缺少 repository.full_name。")
        abort(400, "GitHub 负载中缺少 repository.full_name")

    config = github_repo_configs.get(repo_full_name)
    if not config:
        logger.error(f"错误: 未找到 GitHub 仓库 {repo_full_name} 的配置。")
        abort(404, f"未找到 GitHub 仓库 {repo_full_name} 的配置。请通过 /config/github/repo 端点进行配置。")

    webhook_secret = config.get('secret')
    access_token = config.get('token')

    if not verify_github_signature(request, webhook_secret):
        abort(401, "GitHub signature verification failed.")

    event_type = request.headers.get('X-GitHub-Event')
    if event_type == "push":
        logger.info("GitHub: 收到 push 事件，转发到 /github_push_webhook 处理。")
        return github_push_webhook()
    if event_type != "pull_request":
        logger.info(f"GitHub: 忽略事件类型: {event_type}")
        return "事件已忽略", 200

    action = payload_data.get('action')
    pr_data = payload_data.get('pull_request', {})
    pr_state = pr_data.get('state')  # 'open', 'closed'
    pr_merged = pr_data.get('merged', False)  # True if merged

    if action == 'closed':
        pull_number_str = str(pr_data.get('number'))
        logger.info(
            f"GitHub: PR {repo_full_name}#{pull_number_str} 已关闭 (合并状态: {pr_merged})。正在清理 Redis 记录...")
        remove_processed_commit_entries_for_pr_mr('github', repo_full_name, pull_number_str)
        return f"PR {pull_number_str} 已关闭，记录已清理。", 200

    if pr_state != 'open' or action not in ['opened', 'reopened', 'synchronize']:
        logger.info(f"GitHub: 忽略 PR 操作 '{action}' 或状态 '{pr_state}'。")
        return "PR 操作/状态已忽略", 200

    owner = repo_info.get('owner', {}).get('login')
    repo_name = repo_info.get('name')
    pull_number = pr_data.get('number')
    pr_title = pr_data.get('title')
    pr_html_url = pr_data.get('html_url')
    head_sha = pr_data.get('head', {}).get('sha')
    repo_web_url = repo_info.get('html_url')
    pr_source_branch = pr_data.get('head', {}).get('ref')
    pr_target_branch = pr_data.get('base', {}).get('ref')

    if not all([owner, repo_name, pull_number, head_sha]):
        logger.error("错误: GitHub 负载中缺少必要的 PR 信息。")
        abort(400, "GitHub 负载中缺少必要的 PR 信息")

    logger.info(f"--- 收到 GitHub Pull Request Hook (详细审查) ---")
    logger.info(f"仓库: {repo_full_name}, PR 编号: {pull_number}, Head SHA: {head_sha}")

    if head_sha and is_commit_processed('github', repo_full_name, str(pull_number), head_sha):
        logger.info(f"GitHub (详细审查): PR {repo_full_name}#{pull_number} 的提交 {head_sha} 已处理。跳过。")
        return "提交已处理", 200

    # 调用提取出来的核心处理逻辑函数 (异步执行)
    future = executor.submit(hook.routes_detailed._process_github_detailed_payload, access_token=access_token, owner=owner,
                             repo_name=repo_name, pull_number=pull_number, head_sha=head_sha,
                             repo_full_name=repo_full_name, pr_title=pr_title, pr_html_url=pr_html_url,
                             repo_web_url=repo_web_url, pr_source_branch=pr_source_branch,
                             pr_target_branch=pr_target_branch)
    future.add_done_callback(handle_async_task_exception)

    logger.info(f"GitHub (详细审查): PR {repo_full_name}#{pull_number} 的处理任务已提交到后台执行。")
    return jsonify({"message": "GitHub Detailed Webhook processing task accepted."}), 202


@app.route('/gitlab_webhook_general', methods=['POST'])
def gitlab_webhook_general():
    """处理 GitLab Webhook 请求 (粗粒度审查)"""
    try:
        data = request.get_json()
        if data is None: raise ValueError("请求体为空或非有效 JSON")
    except Exception as e:
        logger.error(f"解析 GitLab JSON 负载时出错 (粗粒度): {e}")
        abort(400, "无效的 JSON 负载")

    project_data = data.get('project', {})
    project_id = project_data.get('id')
    project_web_url = project_data.get('web_url')
    project_name_from_payload = project_data.get('name')
    mr_attrs = data.get('object_attributes', {})
    mr_iid = mr_attrs.get('iid')
    mr_title = mr_attrs.get('title')
    mr_url = mr_attrs.get('url')
    last_commit_payload = mr_attrs.get('last_commit', {})
    head_sha_payload = last_commit_payload.get('id')  # SHA from hook payload

    if not project_id or not mr_iid:
        logger.error("错误: GitLab 负载中缺少 project_id 或 mr_iid (粗粒度)。")
        abort(400, "GitLab 负载中缺少 project_id 或 mr_iid")

    project_id_str = str(project_id)
    config = gitlab_project_configs.get(project_id_str)
    if not config:
        logger.error(f"错误: 未找到 GitLab 项目 ID {project_id_str} 的配置 (粗粒度)。")
        abort(404, f"未找到 GitLab 项目 {project_id_str} 的配置。")

    webhook_secret = config.get('secret')
    access_token = config.get('token')

    if not verify_gitlab_signature(request, webhook_secret):
        abort(401, "GitLab signature verification failed (general).")

    event_type = request.headers.get('X-Gitlab-Event')
    if event_type != "Merge Request Hook":
        logger.info(f"GitLab (粗粒度): 忽略事件类型: {event_type}")
        return "事件已忽略", 200

    mr_action = mr_attrs.get('action')
    mr_state = mr_attrs.get('state')

    if mr_action in ['close', 'merge'] or mr_state in ['closed', 'merged']:
        mr_iid_str = str(mr_iid)
        logger.info(
            f"GitLab (通用审查): MR {project_id_str}#{mr_iid_str} 已 {mr_action or mr_state}。正在清理已处理的 commit 记录...")
        remove_processed_commit_entries_for_pr_mr('gitlab_general', project_id_str, mr_iid_str)  # Use distinct type
        return f"MR {mr_iid_str} 已 {mr_action or mr_state}，通用审查相关记录已清理。", 200

    if mr_state not in ['opened', 'reopened'] and mr_action != 'update':
        logger.info(f"GitLab (通用审查): 忽略 MR 操作 '{mr_action}' 或状态 '{mr_state}'。")
        return "MR 操作/状态已忽略", 200

    logger.info(f"--- 收到 GitLab Merge Request Hook (通用审查) ---")
    logger.info(f"项目 ID: {project_id_str}, MR IID: {mr_iid}, Head SHA (来自负载): {head_sha_payload}")

    if head_sha_payload and is_commit_processed('gitlab_general', project_id_str, str(mr_iid), head_sha_payload):
        logger.info(f"GitLab (通用审查): MR {project_id_str}#{mr_iid} 的提交 {head_sha_payload} 已处理。跳过。")
        return "提交已处理", 200

    temp_position_info = {"base_commit_sha": mr_attrs.get("diff_base_sha") or mr_attrs.get("base_commit_sha"),
                          "head_commit_sha": head_sha_payload, "start_commit_sha": mr_attrs.get("start_commit_sha")}
    _, version_derived_position_info = get_gitlab_mr_changes(project_id_str, mr_iid, access_token)

    final_position_info = temp_position_info
    if version_derived_position_info:
        final_position_info["base_commit_sha"] = version_derived_position_info.get("base_sha", temp_position_info[
            "base_commit_sha"])
        final_position_info["head_commit_sha"] = version_derived_position_info.get("head_sha", temp_position_info[
            "head_commit_sha"])
        final_position_info["latest_version_id"] = version_derived_position_info.get("id")

    if not final_position_info.get("base_commit_sha") or not final_position_info.get("head_commit_sha"):
        logger.error(f"GitLab (通用审查) MR {project_id_str}#{mr_iid}: 无法确定 base_sha 或 head_sha。中止。")
        return "无法确定提交SHA", 500

    current_commit_sha_for_ops = final_position_info.get("head_commit_sha", head_sha_payload)

    # 调用提取出来的核心处理逻辑函数 (异步执行)
    future = executor.submit(hook.routes_general._process_gitlab_general_payload, access_token=access_token,
                             project_id_str=project_id_str, mr_iid=mr_iid, mr_attrs=mr_attrs,
                             final_position_info=final_position_info, head_sha_payload=head_sha_payload,
                             current_commit_sha_for_ops=current_commit_sha_for_ops,
                             project_name_from_payload=project_name_from_payload, project_web_url=project_web_url,
                             mr_title=mr_title, mr_url=mr_url)
    future.add_done_callback(handle_async_task_exception)

    logger.info(f"GitLab (通用审查): MR {project_id_str}#{mr_iid} 的处理任务已提交到后台执行。")
    return jsonify({"message": "GitLab General Webhook processing task accepted."}), 202


@app.route('/github_webhook_general', methods=['POST'])
def github_webhook_general():
    """处理 GitHub Webhook 请求 (粗粒度审查)"""
    try:
        payload_data = request.get_json()
        if payload_data is None: raise ValueError("请求体为空或非有效 JSON")
    except Exception as e:
        logger.error(f"解析 GitHub JSON 负载时出错 (粗粒度): {e}")
        abort(400, "无效的 JSON 负载")

    repo_info = payload_data.get('repository', {})
    repo_full_name = repo_info.get('full_name')

    if not repo_full_name:
        logger.error("错误: GitHub 负载中缺少 repository.full_name (粗粒度)。")
        abort(400, "GitHub 负载中缺少 repository.full_name")

    config = github_repo_configs.get(repo_full_name)
    if not config:
        logger.error(f"错误: 未找到 GitHub 仓库 {repo_full_name} 的配置 (粗粒度)。")
        abort(404, f"未找到 GitHub 仓库 {repo_full_name} 的配置。")

    webhook_secret = config.get('secret')
    access_token = config.get('token')

    if not verify_github_signature(request, webhook_secret):
        abort(401, "GitHub signature verification failed (general).")

    event_type = request.headers.get('X-GitHub-Event')
    if event_type == "push":
        logger.info("GitHub (粗粒度): 收到 push 事件，转发到 /github_push_webhook 处理。")
        return github_push_webhook()
    if event_type != "pull_request":
        logger.info(f"GitHub (粗粒度): 忽略事件类型: {event_type}")
        return "事件已忽略", 200

    action = payload_data.get('action')
    pr_data = payload_data.get('pull_request', {})
    pr_state = pr_data.get('state')
    pr_merged = pr_data.get('merged', False)

    if action == 'closed':
        pull_number_str = str(pr_data.get('number'))
        logger.info(
            f"GitHub (通用审查): PR {repo_full_name}#{pull_number_str} 已关闭 (合并状态: {pr_merged})。正在清理已处理的 commit 记录...")
        remove_processed_commit_entries_for_pr_mr('github_general', repo_full_name,
                                                  pull_number_str)  # Use distinct type for safety
        return f"PR {pull_number_str} 已关闭，通用审查相关记录已清理。", 200

    if pr_state != 'open' or action not in ['opened', 'reopened', 'synchronize']:
        logger.info(f"GitHub (粗粒度): 忽略 PR 操作 '{action}' 或状态 '{pr_state}'。")
        return "PR 操作/状态已忽略", 200

    owner = repo_info.get('owner', {}).get('login')
    repo_name = repo_info.get('name')
    pull_number = pr_data.get('number')
    pr_title = pr_data.get('title')
    pr_html_url = pr_data.get('html_url')
    head_sha = pr_data.get('head', {}).get('sha')
    repo_web_url = repo_info.get('html_url')
    pr_source_branch = pr_data.get('head', {}).get('ref')
    pr_target_branch = pr_data.get('base', {}).get('ref')

    if not all([owner, repo_name, pull_number, head_sha]):
        logger.error("错误: GitHub 负载中缺少必要的 PR 信息 (粗粒度)。")
        abort(400, "GitHub 负载中缺少必要的 PR 信息")

    logger.info(f"--- 收到 GitHub Pull Request Hook (通用审查) ---")
    logger.info(f"仓库: {repo_full_name}, PR 编号: {pull_number}, Head SHA: {head_sha}")

    if head_sha and is_commit_processed('github_general', repo_full_name, str(pull_number), head_sha):
        logger.info(f"GitHub (通用审查): PR {repo_full_name}#{pull_number} 的提交 {head_sha} 已处理。跳过。")
        return "提交已处理", 200

    # 调用提取出来的核心处理逻辑函数 (异步执行)
    future = executor.submit(hook.routes_general._process_github_general_payload, access_token=access_token, owner=owner,
                             repo_name=repo_name, pull_number=pull_number, pr_data=pr_data, head_sha=head_sha,
                             repo_full_name=repo_full_name, pr_title=pr_title, pr_html_url=pr_html_url,
                             repo_web_url=repo_web_url, pr_source_branch=pr_source_branch,
                             pr_target_branch=pr_target_branch)
    future.add_done_callback(handle_async_task_exception)

    logger.info(f"GitHub (通用审查): PR {repo_full_name}#{pull_number} 的处理任务已提交到后台执行。")
    return jsonify({"message": "GitHub General Webhook processing task accepted."}), 202


@app.route("/github_push_webhook", methods=["POST"])
def github_push_webhook():
    try:
        data = request.get_json()
        if data is None:
            raise ValueError("请求体为空或非有效 JSON")
    except Exception as e:
        logger.error(f"解析 GitHub JSON 负载时出错: {e}")
        abort(400, "无效的 JSON 负载")

    event_type = request.headers.get("X-GitHub-Event")
    if event_type != "push":
        logger.info(f"GitHub (Push): 忽略事件类型: {event_type}")
        return "ignored", 200

    repo_data = data.get("repository", {})
    repo_full_name = repo_data.get("full_name")
    if not repo_full_name:
        abort(400, "GitHub 负载中缺少 repository.full_name")

    config = github_repo_configs.get(repo_full_name)
    if not config:
        abort(404, f"未找到 GitHub 仓库 {repo_full_name} 的配置")

    webhook_secret = config.get("secret")
    access_token = config.get("token")
    if not verify_github_signature(request, webhook_secret):
        abort(401, "GitHub signature verification failed.")

    if data.get("deleted"):
        logger.info(f"GitHub (Push): {repo_full_name} 分支删除事件，跳过审计。")
        return jsonify({"message": "Branch deleted. Skipped."}), 200

    ref = data.get("ref") or ""
    before_sha = data.get("before") or ""
    after_sha = data.get("after") or ""
    created = bool(data.get("created", False))
    audit_id = hook.push_process._make_push_audit_id(ref, after_sha)

    owner = (repo_data.get("owner") or {}).get("name") or (repo_data.get("owner") or {}).get("login")
    repo_name = repo_data.get("name")
    default_branch = repo_data.get("default_branch")
    repo_web_url = repo_data.get("html_url")

    if not owner or not repo_name or not ref or not after_sha:
        abort(400, "GitHub Push 负载缺少必要字段 (owner/name/ref/after)")

    if is_commit_processed("github_push", repo_full_name, audit_id, after_sha):
        logger.info(f"GitHub (Push): {repo_full_name} {audit_id} {after_sha} 已处理，跳过。")
        return jsonify({"message": "Already processed."}), 200

    future = executor.submit(hook.push_process._process_github_push_payload, access_token=access_token, owner=owner,
                             repo_name=repo_name, repo_full_name=repo_full_name, ref=ref, audit_id=audit_id,
                             before_sha=before_sha, after_sha=after_sha, created=created, default_branch=default_branch,
                             repo_web_url=repo_web_url, )
    future.add_done_callback(handle_async_task_exception)
    return jsonify({"message": "GitHub Push audit task accepted."}), 202


@app.route("/gitlab_push_webhook", methods=["POST"])
def gitlab_push_webhook():
    try:
        data = request.get_json()
        if data is None:
            raise ValueError("请求体为空或非有效 JSON")
    except Exception as e:
        logger.error(f"解析 GitLab JSON 负载时出错: {e}")
        abort(400, "无效的 JSON 负载")

    event_type = request.headers.get("X-Gitlab-Event")
    if event_type != "Push Hook":
        logger.info(f"GitLab (Push): 忽略事件类型: {event_type}")
        return "ignored", 200

    project_id = data.get("project_id") or (data.get("project") or {}).get("id")
    if not project_id:
        abort(400, "GitLab 负载中缺少 project_id")
    project_id_str = str(project_id)

    config = gitlab_project_configs.get(project_id_str)
    if not config:
        abort(404, f"未找到 GitLab 项目 {project_id_str} 的配置")

    webhook_secret = config.get("secret")
    access_token = config.get("token")
    if not verify_gitlab_signature(request, webhook_secret):
        abort(401, "GitLab signature verification failed.")

    if data.get("after") == "0" * 40 or data.get("checkout_sha") == "0" * 40:
        logger.info(f"GitLab (Push): {project_id_str} 分支删除事件，跳过审计。")
        return jsonify({"message": "Branch deleted. Skipped."}), 200

    ref = data.get("ref") or ""
    before_sha = data.get("before") or ""
    after_sha = data.get("after") or ""
    created = bool(data.get("before") == "0" * 40)
    audit_id = hook.push_process._make_push_audit_id(ref, after_sha)
    default_branch = (data.get("project") or {}).get("default_branch")
    project_name = (data.get("project") or {}).get("name")
    project_web_url = (data.get("project") or {}).get("web_url")

    if not ref or not after_sha:
        abort(400, "GitLab Push 负载缺少必要字段 (ref/after)")

    if is_commit_processed("gitlab_push", project_id_str, audit_id, after_sha):
        logger.info(f"GitLab (Push): {project_id_str} {audit_id} {after_sha} 已处理，跳过。")
        return jsonify({"message": "Already processed."}), 200

    future = executor.submit(hook.push_process._process_gitlab_push_payload, access_token=access_token,
                             project_id_str=project_id_str, ref=ref, audit_id=audit_id, before_sha=before_sha,
                             after_sha=after_sha, project_name=project_name, project_web_url=project_web_url,
                             created=created, default_branch=default_branch, )
    future.add_done_callback(handle_async_task_exception)
    return jsonify({"message": "GitLab Push audit task accepted."}), 202


# --- 主程序入口 ---
if __name__ == '__main__':
    # 配置日志记录
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        handlers=[logging.StreamHandler()])  # 输出到控制台
    logger = logging.getLogger(__name__)

    logger.info(f"启动统一代码审查 Webhook 服务于 {SERVER_HOST}:{SERVER_PORT}")

    # Initial call to set up the client based on initial configs
    initialize_openai_client()

    # 初始化 Redis 客户端并加载配置
    logger.info("--- 持久化配置 ---")
    try:
        if init_redis_client() is None:
            logger.critical("关键错误: Redis 配置错误")
            logger.critical(
                "服务无法启动。请确保 Redis 相关环境变量 (如 REDIS_HOST, REDIS_PORT) 已正确设置，并且 Redis 服务可用。")
            sys.exit(1)
        logger.info(f"Redis 连接: 成功连接到 {app_configs.get('REDIS_HOST')}:{app_configs.get('REDIS_PORT')}")
        load_configs_from_redis()  # 这会填充 github_repo_configs 和 gitlab_project_configs
    except (ValueError, redis.exceptions.ConnectionError) as e:
        logger.critical(f"关键错误: Redis 初始化失败 - {e}")
        logger.critical(
            "服务无法启动。请确保 Redis 相关环境变量 (如 REDIS_HOST, REDIS_PORT) 已正确设置，并且 Redis 服务可用。")
        sys.exit(1)

    logger.info("--- 当前应用配置 ---")
    for key, value in app_configs.items():
        if "KEY" in key.upper() or "TOKEN" in key.upper() or "PASSWORD" in key.upper() or "SECRET" in key.upper():  # Basic redaction for logs
            if value and len(value) > 8:
                logger.info(f"  {key}: ...{value[-4:]}")
            elif value:
                logger.info(f"  {key}: <已设置>")
            else:
                logger.info(f"  {key}: <未设置>")
        else:
            logger.info(f"  {key}: {value}")

    if ADMIN_API_KEY == "change_this_unified_secret_key":
        logger.critical("严重警告: ADMIN_API_KEY 正在使用默认的不安全值。请通过环境变量设置一个强密钥。")
    else:
        logger.info("Admin API 密钥已配置 (从环境加载)。")

    if not app_configs.get("WECOM_BOT_WEBHOOK_URL"):
        logger.info("提示: WECOM_BOT_WEBHOOK_URL 未设置。企业微信机器人通知将被禁用。")
    else:
        url_parts = app_configs.get("WECOM_BOT_WEBHOOK_URL").split('?')
        key_preview = app_configs.get("WECOM_BOT_WEBHOOK_URL")[-6:] if len(
            app_configs.get("WECOM_BOT_WEBHOOK_URL")) > 6 else ''
        logger.info(f"企业微信机器人通知已启用，URL: {url_parts[0]}?key=...{key_preview}")

    if not app_configs.get("CUSTOM_WEBHOOK_URL"):
        logger.info("提示: CUSTOM_WEBHOOK_URL 未设置。自定义 Webhook 通知将被禁用。")
    else:
        logger.info(f"自定义 Webhook 通知已启用，URL: {app_configs.get('CUSTOM_WEBHOOK_URL')}")

    # Check openai_client status after initial attempt
    if not llm_service_module.openai_client:  # Check via module attribute
        logger.warning(
            "警告: OpenAI 客户端无法根据当前设置初始化。在通过管理面板或环境变量提供有效的 OpenAI 配置之前，AI 审查功能将无法工作。")

    # Redis 状态的日志记录已在初始化部分处理，如果程序运行到此处，说明 Redis 已成功连接。
    # 此处不再需要重复的 Redis 状态日志。

    logger.info("--- 配置管理 API ---")
    logger.info("使用 /config/* 端点管理密钥和令牌。")
    logger.info("需要带有从环境加载的 ADMIN_API_KEY 的 'X-Admin-API-Key' 请求头。")
    logger.info(f"管理页面位于: http://localhost:{SERVER_PORT}/admin")

    logger.info("全局设置配置 (通过管理面板或 API):")
    logger.info(
        f"  查看: curl -X GET -H \"X-Admin-API-Key: YOUR_ADMIN_KEY\" http://localhost:{SERVER_PORT}/config/global_settings")
    logger.info(f"  更新: curl -X POST -H \"Content-Type: application/json\" -H \"X-Admin-API-Key: YOUR_ADMIN_KEY\" \\")
    logger.info(
        f"    -d '{{\"OPENAI_MODEL\": \"gpt-3.5-turbo\", \"WECOM_BOT_WEBHOOK_URL\": \"YOUR_WECOM_URL\", \"CUSTOM_WEBHOOK_URL\": \"YOUR_CUSTOM_URL\"}}' \\")  # Example
    logger.info(f"    http://localhost:{SERVER_PORT}/config/global_settings")

    logger.info("GitHub 仓库配置示例 (通过管理面板或 API):")
    logger.info(
        f"  添加/更新: curl -X POST -H \"Content-Type: application/json\" -H \"X-Admin-API-Key: YOUR_ADMIN_KEY\" \\")
    logger.info(
        f"    -d '{{\"repo_full_name\": \"owner/repo\", \"secret\": \"YOUR_GH_WEBHOOK_SECRET\", \"token\": \"YOUR_GITHUB_TOKEN\"}}' \\")
    logger.info(f"    http://localhost:{SERVER_PORT}/config/github/repo")
    logger.info(
        f"  删除: curl -X DELETE -H \"X-Admin-API-Key: YOUR_ADMIN_KEY\" http://localhost:{SERVER_PORT}/config/github/repo/owner/repo")
    logger.info(
        f"  列表: curl -X GET -H \"X-Admin-API-Key: YOUR_ADMIN_KEY\" http://localhost:{SERVER_PORT}/config/github/repos")

    logger.info("GitLab 项目配置示例 (通过管理面板或 API):")
    logger.info(
        f"  添加/更新: curl -X POST -H \"Content-Type: application/json\" -H \"X-Admin-API-Key: YOUR_ADMIN_KEY\" \\")
    logger.info(
        f"    -d '{{\"project_id\": 123, \"secret\": \"YOUR_GL_WEBHOOK_SECRET\", \"token\": \"YOUR_GITLAB_TOKEN\"}}' \\")
    logger.info(f"    http://localhost:{SERVER_PORT}/config/gitlab/project")
    logger.info(
        f"  删除: curl -X DELETE -H \"X-Admin-API-Key: YOUR_ADMIN_KEY\" http://localhost:{SERVER_PORT}/config/gitlab/project/123")
    logger.info(
        f"  列表: curl -X GET -H \"X-Admin-API-Key: YOUR_ADMIN_KEY\" http://localhost:{SERVER_PORT}/config/gitlab/projects")

    logger.info("--- Webhook 端点 ---")
    logger.info(f"GitHub Webhook URL (详细审查): http://localhost:{SERVER_PORT}/github_webhook")
    logger.info(f"GitHub Webhook URL (通用审查): http://localhost:{SERVER_PORT}/github_webhook_general")
    logger.info(f"GitHub Webhook URL (Push 审计): http://localhost:{SERVER_PORT}/github_push_webhook")
    logger.info(f"GitLab Webhook URL (详细审查): http://localhost:{SERVER_PORT}/gitlab_webhook")
    logger.info(f"GitLab Webhook URL (通用审查): http://localhost:{SERVER_PORT}/gitlab_webhook_general")
    logger.info(f"GitLab Webhook URL (Push 审计): http://localhost:{SERVER_PORT}/gitlab_push_webhook")
    logger.info("--- ---")

    # 注册 atexit 处理函数以关闭 ThreadPoolExecutor
    atexit.register(lambda: executor.shutdown(wait=True))
    logger.info("ThreadPoolExecutor shutdown hook registered.")

    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=False)
