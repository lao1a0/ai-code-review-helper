import atexit
import json
import logging
import re
import sys  # 新增导入
from concurrent.futures import ThreadPoolExecutor
from flask import render_template, redirect, Flask
from flask import request, abort, jsonify
import redis
import services.llm_service as llm_service_module
import hook.push_process
import hook.routes_detailed
import hook.routes_general
import config.core_config as core_config_module
from config.core_config import gitlab_project_configs, remove_processed_commit_entries_for_pr_mr, \
    is_commit_processed, github_repo_configs, SERVER_HOST, SERVER_PORT, init_redis_client, app_configs, \
    load_configs_from_redis, ADMIN_API_KEY
from services.llm_service import initialize_openai_client
from services.vcs_service import get_gitlab_mr_changes
from config.utils import verify_github_signature, verify_gitlab_signature, require_admin_key
from hook.helpers import handle_async_task_exception
from config.config_routes import app as config_app
from web_console_routes import app as console_app

# NOTE: config.core_config loads .env at import time so module-level settings like
# ADMIN_API_KEY are correct even when core_config is imported indirectly (e.g., via
# services.*) before this file runs.
app = Flask(__name__, template_folder='web/templates', static_folder='web/static')
# 注册配置相关的路由
app.register_blueprint(config_app)
app.register_blueprint(console_app)

executor = ThreadPoolExecutor(max_workers=20)  # 您可以根据需要调整 max_workers

@app.route('/review_results')
def review_results_page():
    """提供AI审查记录查看页面的 HTML 页面"""
    return redirect('/console')


@app.route('/')
def index():
    return redirect('/console')


@app.route('/chat')
def chat_page():
    return redirect('/console')


@app.route('/admin')
def admin_page():
    return redirect('/console')


def _mask_secret(value: str) -> str:
    if not value:
        return "<empty>"
    if len(value) <= 8:
        return "<set>"
    return f"...{value[-4:]}"


def _extract_kv_pairs(text: str) -> dict:
    """
    Extract key/value pairs from free-form text.
    Supports:
      - key=value
      - key: value
      - key：value
    Values may be quoted.
    """
    pairs = {}
    key_re = r"(repo_full_name|repo|owner_repo|project_id|secret|token|instance_url|url)"
    val_re = r"(\"[^\"]*\"|'[^']*'|[^\\s,]+)"
    for m in re.finditer(key_re + r"\s*[:=：]\s*" + val_re, text, flags=re.IGNORECASE):
        k = (m.group(1) or "").lower()
        v = (m.group(2) or "").strip()
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            v = v[1:-1]
        pairs[k] = v
    return pairs


def _parse_agent_command(message: str) -> dict:
    msg = (message or "").strip()
    if not msg:
        return {"action": "noop"}

    lowered = msg.lower()

    if lowered in {"help", "?", "h", "\u5e2e\u52a9"} or "\u5e2e\u52a9" in msg:
        return {"action": "help"}

    # JSON-first (more reliable).
    if msg.startswith("{") and msg.endswith("}"):
        try:
            payload = json.loads(msg)
            if isinstance(payload, dict) and payload.get("action"):
                return payload
        except Exception:
            pass

    if ("\u5217\u51fa" in msg or "list" in lowered) and "github" in lowered:
        return {"action": "github_list"}
    if ("\u5217\u51fa" in msg or "list" in lowered) and "gitlab" in lowered:
        return {"action": "gitlab_list"}

    if ("\u5220\u9664" in msg or "delete" in lowered) and "github" in lowered:
        repo_match = re.search(r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", msg)
        return {"action": "github_delete", "repo_full_name": repo_match.group(1) if repo_match else None}
    if ("\u5220\u9664" in msg or "delete" in lowered) and "gitlab" in lowered:
        pid_match = re.search(r"\b(\d+)\b", msg)
        return {"action": "gitlab_delete", "project_id": pid_match.group(1) if pid_match else None}

    if ("\u6dfb\u52a0" in msg or "add" in lowered or "\u66f4\u65b0" in msg or "update" in lowered) and "github" in lowered:
        repo_match = re.search(r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", msg)
        kv = _extract_kv_pairs(msg)
        return {
            "action": "github_add",
            "repo_full_name": kv.get("repo_full_name") or kv.get("repo") or (repo_match.group(1) if repo_match else None),
            "secret": kv.get("secret"),
            "token": kv.get("token"),
        }

    if ("\u6dfb\u52a0" in msg or "add" in lowered or "\u66f4\u65b0" in msg or "update" in lowered) and "gitlab" in lowered:
        kv = _extract_kv_pairs(msg)
        pid_match = re.search(r"\b(\d+)\b", msg)
        return {
            "action": "gitlab_add",
            "project_id": kv.get("project_id") or (pid_match.group(1) if pid_match else None),
            "secret": kv.get("secret"),
            "token": kv.get("token"),
            "instance_url": kv.get("instance_url") or kv.get("url"),
        }

    return {"action": "unknown", "message": msg}


def _agent_help_text() -> str:
    return (
        "我可以帮你配置 GitHub / GitLab。\\n\\n"
        "常用指令：\\n"
        "- 列出 GitHub 仓库\\n"
        "- 添加 GitHub：owner/repo secret=xxx token=yyy\\n"
        "- 删除 GitHub：owner/repo\\n"
        "- 列出 GitLab 项目\\n"
        "- 添加 GitLab：project_id=123 secret=xxx token=yyy (instance_url 可选)\\n"
        "- 删除 GitLab：project_id=123\\n\\n"
        "也可以直接发 JSON（更稳定）：\\n"
        "{\\\"action\\\":\\\"github_add\\\",\\\"repo_full_name\\\":\\\"owner/repo\\\",\\\"secret\\\":\\\"xxx\\\",\\\"token\\\":\\\"yyy\\\"}\\n"
        "{\\\"action\\\":\\\"gitlab_add\\\",\\\"project_id\\\":\\\"123\\\",\\\"secret\\\":\\\"xxx\\\",\\\"token\\\":\\\"yyy\\\",\\\"instance_url\\\":\\\"https://gitlab.example.com\\\"}"
    )


def _agent_help_text() -> str:
    # ASCII-only source to avoid mojibake if the file encoding is mis-detected.
    return (
        "\u6211\u53ef\u4ee5\u5e2e\u4f60\u914d\u7f6e GitHub / GitLab\u3002\n\n"
        "\u5e38\u7528\u6307\u4ee4\uff1a\n"
        "- \u5217\u51fa GitHub \u4ed3\u5e93\n"
        "- \u6dfb\u52a0 GitHub\uff1aowner/repo secret=xxx token=yyy\n"
        "- \u5220\u9664 GitHub\uff1aowner/repo\n"
        "- \u5217\u51fa GitLab \u9879\u76ee\n"
        "- \u6dfb\u52a0 GitLab\uff1aproject_id=123 secret=xxx token=yyy (instance_url \u53ef\u9009)\n"
        "- \u5220\u9664 GitLab\uff1aproject_id=123\n\n"
        "\u4e5f\u53ef\u4ee5\u76f4\u63a5\u53d1 JSON\uff08\u66f4\u7a33\u5b9a\uff09\uff1a\n"
        "{\"action\":\"github_add\",\"repo_full_name\":\"owner/repo\",\"secret\":\"xxx\",\"token\":\"yyy\"}\n"
        "{\"action\":\"gitlab_add\",\"project_id\":\"123\",\"secret\":\"xxx\",\"token\":\"yyy\",\"instance_url\":\"https://gitlab.example.com\"}"
    )


@app.route('/api/agent/chat', methods=['POST'])
@require_admin_key
def agent_chat_api():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "Missing field: message"}), 400

    cmd = _parse_agent_command(message)
    action = (cmd.get("action") or "").strip()

    if action == "help":
        return jsonify({"reply": _agent_help_text()}), 200

    if action == "github_list":
        repos = sorted(list(github_repo_configs.keys()))
        if not repos:
            return jsonify({"reply": "当前没有配置任何 GitHub 仓库。"}), 200
        return jsonify({"reply": "已配置的 GitHub 仓库：\n- " + "\n- ".join(repos)}), 200

    if action == "gitlab_list":
        projects = sorted(list(gitlab_project_configs.keys()), key=lambda x: int(x) if str(x).isdigit() else str(x))
        if not projects:
            return jsonify({"reply": "当前没有配置任何 GitLab 项目。"}), 200
        return jsonify({"reply": "已配置的 GitLab 项目：\n- " + "\n- ".join(projects)}), 200

    if action == "github_delete":
        repo_full_name = cmd.get("repo_full_name")
        if not repo_full_name:
            return jsonify({"reply": "请提供要删除的 GitHub 仓库全名，例如：删除 GitHub：owner/repo"}), 200
        if repo_full_name not in github_repo_configs:
            return jsonify({"reply": f"未找到 GitHub 仓库配置：{repo_full_name}"}), 200
        del github_repo_configs[repo_full_name]
        if core_config_module.redis_client:
            try:
                core_config_module.redis_client.hdel(core_config_module.REDIS_GITHUB_CONFIGS_KEY, repo_full_name)
            except Exception:
                logger.exception("Failed to delete GitHub config from Redis: %s", repo_full_name)
        return jsonify({"reply": f"已删除 GitHub 仓库配置：{repo_full_name}"}), 200

    if action == "gitlab_delete":
        project_id = cmd.get("project_id")
        if not project_id:
            return jsonify({"reply": "请提供要删除的 GitLab project_id，例如：删除 GitLab：project_id=123"}), 200
        project_id_str = str(project_id)
        if project_id_str not in gitlab_project_configs:
            return jsonify({"reply": f"未找到 GitLab 项目配置：{project_id_str}"}), 200
        del gitlab_project_configs[project_id_str]
        if core_config_module.redis_client:
            try:
                core_config_module.redis_client.hdel(core_config_module.REDIS_GITLAB_CONFIGS_KEY, project_id_str)
            except Exception:
                logger.exception("Failed to delete GitLab config from Redis: %s", project_id_str)
        return jsonify({"reply": f"已删除 GitLab 项目配置：{project_id_str}"}), 200

    if action == "github_add":
        repo_full_name = (cmd.get("repo_full_name") or "").strip()
        secret = (cmd.get("secret") or "").strip()
        token = (cmd.get("token") or "").strip()
        missing = [k for k, v in (("repo_full_name", repo_full_name), ("secret", secret), ("token", token)) if not v]
        if missing:
            return jsonify({"reply": "缺少字段：" + ", ".join(missing) + "\n\n" + _agent_help_text()}), 200

        config_data = {"secret": secret, "token": token}
        github_repo_configs[repo_full_name] = config_data
        if core_config_module.redis_client:
            try:
                core_config_module.redis_client.hset(
                    core_config_module.REDIS_GITHUB_CONFIGS_KEY, repo_full_name, json.dumps(config_data)
                )
            except Exception:
                logger.exception("Failed to save GitHub config to Redis: %s", repo_full_name)

        return jsonify({
            "reply": (
                f"已添加/更新 GitHub 仓库：{repo_full_name}\n"
                f"- secret: {_mask_secret(secret)}\n"
                f"- token: {_mask_secret(token)}"
            )
        }), 200

    if action == "gitlab_add":
        project_id = (cmd.get("project_id") or "").strip()
        secret = (cmd.get("secret") or "").strip()
        token = (cmd.get("token") or "").strip()
        instance_url = (cmd.get("instance_url") or "").strip()
        missing = [k for k, v in (("project_id", project_id), ("secret", secret), ("token", token)) if not v]
        if missing:
            return jsonify({"reply": "缺少字段：" + ", ".join(missing) + "\n\n" + _agent_help_text()}), 200

        project_id_str = str(project_id)
        config_data = {"secret": secret, "token": token}
        if instance_url:
            config_data["instance_url"] = instance_url
        gitlab_project_configs[project_id_str] = config_data
        if core_config_module.redis_client:
            try:
                core_config_module.redis_client.hset(
                    core_config_module.REDIS_GITLAB_CONFIGS_KEY, project_id_str, json.dumps(config_data)
                )
            except Exception:
                logger.exception("Failed to save GitLab config to Redis: %s", project_id_str)

        reply = (
            f"已添加/更新 GitLab 项目：{project_id_str}\n"
            f"- secret: {_mask_secret(secret)}\n"
            f"- token: {_mask_secret(token)}"
        )
        if instance_url:
            reply += f"\n- instance_url: {instance_url}"
        return jsonify({"reply": reply}), 200

    return jsonify({"reply": "我没理解你的输入。\n\n" + _agent_help_text()}), 200


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
            if value:
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
    logger.info(f"控制台页面位于: http://localhost:{SERVER_PORT}/console")

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
