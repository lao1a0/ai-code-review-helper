import logging
from concurrent.futures import ThreadPoolExecutor

from flask import Blueprint, abort, current_app, jsonify, request

from config.postgres_config import (gitlab_project_configs, github_repo_configs, )
from services.langchain_agent import run_langchain_agent
from utils.agent_commands import agent_help_text, parse_agent_command
from utils.auth import require_admin_key, verify_github_signature, verify_gitlab_signature
from webhooks import push_process, routes_detailed
from webhooks.helpers import handle_async_task_exception, run_with_app_context

logger = logging.getLogger(__name__)

bp = Blueprint("webhooks_app", __name__)
executor = ThreadPoolExecutor(max_workers=20)


@bp.route("/api/agent/chat", methods=["POST"])
@require_admin_key
def agent_chat_api():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "Missing field: message"}), 400

    try:
        reply = run_langchain_agent(message)
        if reply:
            return jsonify({"reply": reply}), 200
    except Exception:
        logger.exception("LangChain agent failed; falling back to rule-based agent.")

    cmd = parse_agent_command(message)
    if (cmd.get("action") or "").strip() == "help":
        return jsonify({"reply": agent_help_text()}), 200
    return jsonify({"reply": "我没理解你的输入。\n\n" + agent_help_text()}), 200


@bp.route("/gitlab_webhook", methods=["POST"])
def gitlab_webhook():
    # GitLab webhook的详细处理逻辑在routes_detailed模块中
    event_type = request.headers.get("X-Gitlab-Event")
    if event_type == "Push Hook":
        return gitlab_push_webhook()
    if event_type != "Merge Request Hook":
        return "事件已忽略", 200

    # 处理Merge Request事件
    try:
        data = request.get_json()
        if data is None:
            raise ValueError("请求体为空或非有效 JSON")
    except Exception as e:
        logger.error("解析 GitLab JSON 负载时出错: %s", e)
        abort(400, "无效的 JSON 负载")

    project_data = data.get("project", {})
    project_id = project_data.get("id")
    project_web_url = project_data.get("web_url")
    project_name_from_payload = project_data.get("name")
    mr_attrs = data.get("object_attributes", {})
    mr_iid = mr_attrs.get("iid")
    mr_title = mr_attrs.get("title")
    mr_url = mr_attrs.get("url")
    last_commit = mr_attrs.get("last_commit", {})
    head_sha_payload = last_commit.get("id")

    if not project_id or not mr_iid:
        abort(400, "GitLab 负载中缺少 project_id 或 mr_iid")

    project_id_str = str(project_id)
    config = gitlab_project_configs.get(project_id_str)
    if not config:
        abort(404, f"未找到 GitLab 项目 {project_id_str} 的配置。请通过 /config/gitlab/project 端点进行配置。")

    webhook_secret = config.get("secret")
    access_token = config.get("token")
    if not verify_gitlab_signature(request, webhook_secret):
        abort(401, "GitLab signature verification failed.")

    mr_action = mr_attrs.get("action")
    mr_state = mr_attrs.get("state")
    if mr_action in ["close", "merge"] or mr_state in ["closed", "merged"]:
        mr_iid_str = str(mr_iid)
        return f"MR {mr_iid_str} 已关闭/合并，记录已清理。", 200

    if mr_state not in ["opened", "reopened"] and mr_action != "update":
        return "MR 操作/状态已忽略 (非审查触发条件)", 200

    app = current_app._get_current_object()
    future = executor.submit(run_with_app_context, app, routes_detailed._process_gitlab_detailed_payload,
                             access_token=access_token, project_id_str=project_id_str, mr_iid=mr_iid,
                             head_sha_payload=head_sha_payload, project_data=project_data, mr_attrs=mr_attrs,
                             project_web_url=project_web_url, mr_title=mr_title, mr_url=mr_url,
                             project_name_from_payload=project_name_from_payload, )
    future.add_done_callback(lambda f: handle_async_task_exception(f, logger_app_factory=logger))
    return jsonify({"message": "GitLab Detailed Webhook processing task accepted."}), 202


@bp.route("/github_webhook", methods=["POST"])
def github_webhook():
    # 处理GitHub webhook事件
    event_type = request.headers.get("X-GitHub-Event")
    if event_type == "push":
        return github_push_webhook()
    if event_type != "pull_request":
        return "事件已忽略", 200

    # 处理Pull Request事件
    payload_data = request.get_json()
    if payload_data is None:
        raise ValueError("请求体为空或非有效 JSON")

    repo_info = payload_data.get("repository", {})
    repo_full_name = repo_info.get("full_name")
    if not repo_full_name:
        logger.error("GitHub 负载中缺少 repository.full_name")
        return jsonify({"message": "GitHub 负载中缺少 repository.full_name"}, 400)

    config = github_repo_configs.get(repo_full_name)
    if not config:
        logger.error(f"未找到 GitHub 仓库 {repo_full_name} 的配置。请通过 /config/github/repo 端点进行配置。")
        return jsonify({"message": "未找到 GitHub 仓库的配置"}, 404)

    webhook_secret = config.get("secret")
    access_token = config.get("token")
    if not verify_github_signature(request, webhook_secret):
        logger.error("GitHub signature verification failed.")
        return jsonify({"message": "GitHub signature verification failed."}, 401)

    action = payload_data.get("action")
    pr_data = payload_data.get("pull_request", {})
    pr_state = pr_data.get("state")

    if action == "closed":
        pull_number_str = str(pr_data.get("number"))
        return f"PR {pull_number_str} 已关闭，记录已清理。", 200

    if pr_state != "open" or action not in ["opened", "reopened", "synchronize"]:
        return "PR 操作/状态已忽略", 200

    owner = repo_info.get("owner", {}).get("login")
    repo_name = repo_info.get("name")
    pull_number = pr_data.get("number")
    pr_title = pr_data.get("title")
    pr_html_url = pr_data.get("html_url")
    head_sha = pr_data.get("head", {}).get("sha")
    repo_web_url = repo_info.get("html_url")
    pr_source_branch = pr_data.get("head", {}).get("ref")
    pr_target_branch = pr_data.get("base", {}).get("ref")

    if not all([owner, repo_name, pull_number, head_sha]):
        return jsonify({"message": "GitHub 负载中缺少必要的 PR 信息"}, 400)

    app = current_app._get_current_object()
    future = executor.submit(run_with_app_context, app, routes_detailed._process_github_detailed_payload,
                             access_token=access_token, owner=owner, repo_name=repo_name, pull_number=pull_number,
                             head_sha=head_sha, repo_full_name=repo_full_name, pr_title=pr_title,
                             pr_html_url=pr_html_url, repo_web_url=repo_web_url, pr_source_branch=pr_source_branch,
                             pr_target_branch=pr_target_branch, )
    future.add_done_callback(lambda f: handle_async_task_exception(f, logger_app_factory=logger))
    return jsonify({"message": "GitHub Detailed Webhook processing task accepted."}), 202


def _handle_push_webhook(platform_config, platform_name, data_getter_func, validation_func=None):
    """
    通用的推送Webhook处理函数
    
    Args:
        platform_config: 平台配置字典 (github_repo_configs 或 gitlab_project_configs)
        platform_name: 平台名称 ('github' 或 'gitlab')
        data_getter_func: 获取数据的函数，用于从payload中提取特定字段
        validation_func: 可选的验证函数，用于验证请求签名等
    
    Returns:
        Flask response
    """
    try:
        data = request.get_json()
        if data is None:
            raise ValueError("请求体为空或非有效 JSON")
    except Exception as e:
        logger.error(f"解析 {platform_name.title()} JSON 负载时出错: %s", e)
        abort(400, f"无效的 JSON 负载")

    # 验证事件类型
    if platform_name == "github":
        event_type = request.headers.get("X-GitHub-Event")
        if event_type != "push":
            return "ignored", 200
    elif platform_name == "gitlab":
        event_type = request.headers.get("X-Gitlab-Event")
        if event_type != "Push Hook":
            return "ignored", 200

    # 获取配置和验证
    identifier, config = data_getter_func(data, platform_config)
    if not config:
        if platform_name == "gitlab":
            abort(404, f"未找到 {platform_name.title()} 项目 {identifier} 的配置")
        else:
            abort(404, f"未找到 {platform_name.title()} 仓库 {identifier} 的配置")

    if validation_func:
        if not validation_func(request, config):
            abort(401, f"{platform_name.title()} signature verification failed.")

    # 检查分支是否被删除
    if data.get("deleted") or data.get("after") == "0" * 40:
        return jsonify({"message": "Branch deleted. Skipped."}), 200

    # 提取通用参数
    ref = data.get("ref") or ""
    before_sha = data.get("before") or ""
    after_sha = data.get("after") or ""
    created = bool(data.get("created", False) if platform_name == "github" else data.get("before") == "0" * 40)
    audit_id = push_process._make_push_audit_id(ref, after_sha)

    # 根据平台获取特定参数
    if platform_name == "github":
        owner = (data.get("repository", {}).get("owner") or {}).get("name") or (
                    data.get("repository", {}).get("owner") or {}).get("login")
        repo_name = data.get("repository", {}).get("name")
        repo_full_name = data.get("repository", {}).get("full_name")
        default_branch = data.get("repository", {}).get("default_branch")
        repo_web_url = data.get("repository", {}).get("html_url")
        access_token = config.get("token")

        # 参数验证
        if not owner or not repo_name or not ref or not after_sha:
            logger.error("GitHub Push 负载缺少必要字段 (owner/name/ref/after)")
            return jsonify({"message": "GitHub Push 负载缺少必要字段 (owner/name/ref/after)。"}), 400

        return _execute_push_task(
            {"access_token": access_token, "owner": owner, "repo_name": repo_name, "repo_full_name": repo_full_name,
                "ref": ref, "audit_id": audit_id, "before_sha": before_sha, "after_sha": after_sha, "created": created,
                "default_branch": default_branch, "repo_web_url": repo_web_url},
            push_process._process_github_push_payload)
    elif platform_name == "gitlab":
        project_id_str = identifier
        default_branch = (data.get("project") or {}).get("default_branch")
        project_name = (data.get("project") or {}).get("name")
        project_web_url = (data.get("project") or {}).get("web_url")
        access_token = config.get("token")

        # 参数验证
        if not ref or not after_sha:
            abort(400, "GitLab Push 负载缺少必要字段 (ref/after)")

        return _execute_push_task(
            {"access_token": access_token, "project_id_str": project_id_str, "ref": ref, "audit_id": audit_id,
                "before_sha": before_sha, "after_sha": after_sha, "project_name": project_name,
                "project_web_url": project_web_url, "created": created, "default_branch": default_branch},
            push_process._process_gitlab_push_payload)


def _execute_push_task(params, process_func):
    """
    执行推送任务的通用函数
    
    Args:
        params: 包含任务参数的字典
        process_func: 要执行的具体处理函数
    
    Returns:
        Flask response
    """
    app = current_app._get_current_object()
    future = executor.submit(run_with_app_context, app, process_func, **params)
    future.add_done_callback(lambda f: handle_async_task_exception(f, logger_app_factory=logger))
    platform_name = "GitHub" if "repo_name" in params else "GitLab"
    return jsonify({"message": f"{platform_name} Push audit task accepted."}), 202


def github_push_webhook():
    def github_data_getter(data, platform_config):
        repo_full_name = data.get("repository", {}).get("full_name")
        config = platform_config.get(repo_full_name)
        return repo_full_name, config

    return _handle_push_webhook(platform_config=github_repo_configs, platform_name="github",
        data_getter_func=github_data_getter, validation_func=verify_github_signature)


def gitlab_push_webhook():
    def gitlab_data_getter(data, platform_config):
        project_id = data.get("project_id") or (data.get("project") or {}).get("id")
        if not project_id:
            abort(400, "GitLab 负载中缺少 project_id")
        project_id_str = str(project_id)
        config = platform_config.get(project_id_str)
        return project_id_str, config

    return _handle_push_webhook(platform_config=gitlab_project_configs, platform_name="gitlab",
        data_getter_func=gitlab_data_getter, validation_func=verify_gitlab_signature)
