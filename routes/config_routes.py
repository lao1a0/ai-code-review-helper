import logging
from flask import Blueprint, request, jsonify
import config.core_config as core_config_module
from config.postgres_config import  get_all_reviewed_prs_mrs_keys,get_review_results
from services.llm_client_manager import initialize_openai_client
from utils.auth import require_admin_key

logger = logging.getLogger(__name__)
bp = Blueprint("config_app", __name__)

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

