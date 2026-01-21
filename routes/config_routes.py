import json
import logging
from flask import Blueprint, request, jsonify
import config.core_config as core_config_module
from config.redis_config import gitlab_project_configs, REDIS_GITLAB_CONFIGS_KEY, github_repo_configs, \
    REDIS_GITHUB_CONFIGS_KEY, get_all_reviewed_prs_mrs_keys, get_review_results, redis_client
from services.llm_client_manager import initialize_openai_client
from utils.auth import require_admin_key

logger = logging.getLogger(__name__)
bp = Blueprint("config_app", __name__)


@bp.route("/config/github/repo", methods=["POST"])
@require_admin_key
def add_or_update_github_repo_config():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    data = request.get_json()
    repo_full_name = data.get("repo_full_name")
    secret = data.get("secret")
    token = data.get("token")
    if not repo_full_name or not secret or not token:
        return jsonify({"error": "Missing required fields: repo_full_name, secret, token"}), 400

    config_data = {"secret": secret, "token": token}
    github_repo_configs[repo_full_name] = config_data

    if redis_client:
        try:
            redis_client.hset(REDIS_GITHUB_CONFIGS_KEY, repo_full_name, json.dumps(config_data))
            logger.info("GitHub config %s saved to Redis.", repo_full_name)
        except Exception as e:
            logger.error("Failed to save GitHub config %s to Redis: %s", repo_full_name, e)

    return jsonify({"message": f"Configuration for GitHub repository {repo_full_name} added/updated."}), 200


@bp.route("/config/github/repo/<path:repo_full_name>", methods=["DELETE"])
@require_admin_key
def delete_github_repo_config(repo_full_name):
    if repo_full_name in github_repo_configs:
        del github_repo_configs[repo_full_name]
        if redis_client:
            try:
                redis_client.hdel(REDIS_GITHUB_CONFIGS_KEY, repo_full_name)
                logger.info("GitHub config %s deleted from Redis.", repo_full_name)
            except Exception as e:
                logger.error("Failed to delete GitHub config %s from Redis: %s", repo_full_name, e)
        return jsonify({"message": f"Configuration for GitHub repository {repo_full_name} deleted."}), 200
    return jsonify({"error": f"Configuration for GitHub repository {repo_full_name} not found."}), 404


@bp.route("/config/github/repos", methods=["GET"])
@require_admin_key
def list_github_repo_configs():
    return jsonify({"configured_github_repositories": list(github_repo_configs.keys())}), 200


@bp.route("/config/gitlab/project", methods=["POST"])
@require_admin_key
def add_or_update_gitlab_project_config():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    data = request.get_json()
    project_id = data.get("project_id")
    secret = data.get("secret")
    token = data.get("token")
    instance_url = data.get("instance_url")

    if not project_id or not secret or not token:
        return jsonify({"error": "Missing required fields: project_id, secret, token"}), 400

    project_id_str = str(project_id)
    config_data = {"secret": secret, "token": token}
    if instance_url:
        config_data["instance_url"] = instance_url

    gitlab_project_configs[project_id_str] = config_data
    if redis_client:
        try:
            redis_client.hset(REDIS_GITLAB_CONFIGS_KEY, project_id_str, json.dumps(config_data))
            logger.info("GitLab config %s saved to Redis.", project_id_str)
        except Exception as e:
            logger.error("Failed to save GitLab config %s to Redis: %s", project_id_str, e)

    return jsonify({"message": f"Configuration for GitLab project {project_id_str} added/updated."}), 200


@bp.route("/config/gitlab/project/<string:project_id>", methods=["DELETE"])
@require_admin_key
def delete_gitlab_project_config(project_id):
    project_id_str = str(project_id)
    if project_id_str in gitlab_project_configs:
        del gitlab_project_configs[project_id_str]
        if redis_client:
            try:
                redis_client.hdel(REDIS_GITLAB_CONFIGS_KEY, project_id_str)
                logger.info("GitLab config %s deleted from Redis.", project_id_str)
            except Exception as e:
                logger.error("Failed to delete GitLab config %s from Redis: %s", project_id_str, e)
        return jsonify({"message": f"Configuration for GitLab project {project_id_str} deleted."}), 200
    return jsonify({"error": f"Configuration for GitLab project {project_id_str} not found."}), 404


@bp.route("/config/gitlab/projects", methods=["GET"])
@require_admin_key
def list_gitlab_project_configs():
    return jsonify({"configured_gitlab_projects": list(gitlab_project_configs.keys())}), 200


@bp.route("/config/global_settings", methods=["GET"])
@require_admin_key
def get_global_settings():
    return jsonify({k: v for k, v in core_config_module.app_configs.items()}), 200


@bp.route("/config/global_settings", methods=["POST"])
@require_admin_key
def update_global_settings():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    data = request.get_json()

    updated_keys = []
    openai_config_changed = False
    for key in core_config_module.app_configs.keys():
        if key not in data:
            continue
        incoming_value = data[key]
        try:
            if key in ["LLM_TEMPERATURE", "RAG_SIMILARITY_THRESHOLD", "RAG_HYBRID_WEIGHT"]:
                incoming_value = float(incoming_value)
            elif key in ["LLM_MAX_CONTEXT_TOKENS", "RAG_TOP_K"]:
                incoming_value = int(incoming_value)
        except Exception:
            pass

        if core_config_module.app_configs.get(key) != incoming_value:
            core_config_module.app_configs[key] = incoming_value
            updated_keys.append(key)
            if key in ["OPENAI_API_BASE_URL", "OPENAI_API_KEY", "OPENAI_MODEL"]:
                openai_config_changed = True

    if openai_config_changed:
        initialize_openai_client()

    if updated_keys:
        return jsonify({"message": f"Global settings updated for: {', '.join(updated_keys)}"}), 200
    return jsonify({"message": "No settings were updated or values provided matched existing configuration."}), 200


@bp.route("/config/review_results/list", methods=["GET"])
@require_admin_key
def list_reviewed_prs_mrs():
    reviewed_items = get_all_reviewed_prs_mrs_keys()
    if reviewed_items is None:
        return jsonify({"error": "无法从 Redis 获取审查结果列表。"}), 500
    reviewed_items.sort(key=lambda x: x.get("created_at", ""), reverse=False)
    return jsonify({"reviewed_pr_mr_list": reviewed_items}), 200


@bp.route("/config/review_results/<string:vcs_type>/<path:identifier>/<string:pr_mr_id>", methods=["GET"])
@require_admin_key
def get_specific_review_results(vcs_type, identifier, pr_mr_id):
    commit_sha = request.args.get("commit_sha", None)
    allowed_vcs_types = ["github", "gitlab", "github_general", "gitlab_general", "github_push", "gitlab_push"]
    if vcs_type not in allowed_vcs_types:
        return jsonify({"error": f"无效的 VCS 类型。支持的类型: {', '.join(allowed_vcs_types)}。"}), 400

    results = get_review_results(vcs_type, identifier, pr_mr_id, commit_sha)
    if results is None:
        if commit_sha:
            return jsonify({"error": f"未找到针对 commit {commit_sha} 的审查结果。"}), 404
        return jsonify({"error": "从 Redis 获取审查结果时出错或未找到该 PR/MR 的记录。"}), 500

    if commit_sha:
        return jsonify({"commit_sha": commit_sha, "review_data": results}), 200
    all_commits_reviews = results.get("commits", {})
    project_name = results.get("project_name")
    response_data = {"pr_mr_id": pr_mr_id, "all_reviews_by_commit": all_commits_reviews}
    if project_name:
        response_data["project_name"] = project_name
    return jsonify(response_data), 200

