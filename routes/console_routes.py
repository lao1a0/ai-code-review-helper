import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import yaml
from flask import Blueprint, jsonify, render_template, request

from config.core_config import app_configs
from config.postgres_config import get_all_reviewed_prs_mrs_keys, get_review_results, gitlab_project_configs, github_repo_configs
from db.models import User
from services import app_log, rag_call_graph, rag_service, review_enrichment, settings_store, skill_registry
from services.vcs_service import get_github_pr_changes, get_gitlab_mr_changes
from utils.auth import require_admin_key

logger = logging.getLogger(__name__)

bp = Blueprint("console_app", __name__)


@bp.route("/console")
def console_page():
    return render_template("console.html")


@bp.route("/api/logs", methods=["GET"])
@require_admin_key
def api_logs_list():
    limit = int(request.args.get("limit", "200") or "200")
    limit = max(1, min(limit, 500))
    return jsonify({"events": app_log.list_events(limit=limit)}), 200


@bp.route("/api/logs/clear", methods=["POST"])
@require_admin_key
def api_logs_clear():
    app_log.clear_events()
    return jsonify({"message": "cleared"}), 200


@bp.route("/api/skills", methods=["GET"])
@require_admin_key
def api_skills_list():
    return jsonify({"skills": skill_registry.list_skill_dicts()}), 200


@bp.route("/api/skills/<string:skill_name>", methods=["GET"])
@require_admin_key
def api_skills_read(skill_name: str):
    doc = skill_registry.read_skill_doc(skill_name)
    if not doc:
        return jsonify({"error": "skill not found"}), 404
    app_log.add_event("skill.read", f"Read skill doc: {skill_name}", {"skill": skill_name})
    return jsonify({"name": skill_name, "doc": doc}), 200


@bp.route("/api/prompts", methods=["GET"])
@require_admin_key
def api_prompts_list():
    path = Path("ai_code_review_helper") / "prompt" / "prompt_templates.yml"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        data = {}
    return jsonify({"templates": sorted(list(data.keys()))}), 200


def _project_key(platform: str, identifier: str) -> str:
    platform = (platform or "").lower()
    if platform not in {"github", "gitlab"}:
        platform = "unknown"
    return f"{platform}:{identifier}"


@bp.route("/api/projects", methods=["GET"])
@require_admin_key
def api_projects_list():
    projects = []

    for repo_full_name, conf in (github_repo_configs or {}).items():
        key = _project_key("github", repo_full_name)
        settings = settings_store.get_project_settings(key)
        projects.append({
            "project_key": key,
            "platform": "github",
            "identifier": repo_full_name,
            "has_token": bool((conf or {}).get("token")),
            "has_secret": bool((conf or {}).get("secret")),
            "settings": settings,
        })

    for project_id, conf in (gitlab_project_configs or {}).items():
        project_id_str = str(project_id)
        key = _project_key("gitlab", project_id_str)
        settings = settings_store.get_project_settings(key)
        projects.append({
            "project_key": key,
            "platform": "gitlab",
            "identifier": project_id_str,
            "instance_url": (conf or {}).get("instance_url") or app_configs.get("GITLAB_INSTANCE_URL"),
            "has_token": bool((conf or {}).get("token")),
            "has_secret": bool((conf or {}).get("secret")),
            "settings": settings,
        })

    return jsonify({"projects": projects}), 200


@bp.route("/api/users", methods=["GET"])
@require_admin_key
def api_users_list():
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify({"users": [u.to_dict() for u in users]}), 200


@bp.route("/api/projects/<path:project_key>/settings", methods=["GET"])
@require_admin_key
def api_project_settings_get(project_key: str):
    return jsonify({"project_key": project_key, "settings": settings_store.get_project_settings(project_key)}), 200


@bp.route("/api/projects/<path:project_key>/settings", methods=["POST"])
@require_admin_key
def api_project_settings_set(project_key: str):
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    patch = request.get_json(silent=True) or {}
    updated = settings_store.set_project_settings(project_key, patch)
    app_log.add_event("project.settings.update", f"Updated project settings: {project_key}", {"project_key": project_key})
    return jsonify({"project_key": project_key, "settings": updated}), 200


@bp.route("/api/agent/settings", methods=["GET"])
@require_admin_key
def api_agent_settings_get():
    return jsonify({"settings": settings_store.get_agent_settings()}), 200


@bp.route("/api/agent/settings", methods=["POST"])
@require_admin_key
def api_agent_settings_set():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    patch = request.get_json(silent=True) or {}
    updated = settings_store.set_agent_settings(patch)
    app_log.add_event("agent.settings.update", "Updated agent settings", {})
    return jsonify({"settings": updated}), 200


@bp.route("/api/reviews/list", methods=["GET"])
@require_admin_key
def api_reviews_list():
    reviewed_items = get_all_reviewed_prs_mrs_keys() or []
    reviewed_items.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    include_stats = request.args.get("include_stats", "1") == "1"
    out = []
    for item in reviewed_items:
        vcs_type = item.get("vcs_type") or ""
        identifier = item.get("identifier") or ""
        pr_mr_id = str(item.get("pr_mr_id") or "")
        enriched = {}
        if include_stats:
            try:
                reviews_by_commit = get_review_results(vcs_type, identifier, pr_mr_id) or {}
                enriched = review_enrichment.summarize_review(vcs_type, identifier, pr_mr_id, reviews_by_commit)
            except Exception:
                logger.exception("Failed to enrich review list item")
        out.append({**item, **enriched})

    return jsonify({"reviews": out}), 200


@bp.route("/api/reviews/<string:vcs_type>/<path:identifier>/<string:pr_mr_id>", methods=["GET"])
@require_admin_key
def api_review_detail(vcs_type: str, identifier: str, pr_mr_id: str):
    reviews_by_commit = get_review_results(vcs_type, identifier, pr_mr_id) or {}
    enriched = review_enrichment.summarize_review(vcs_type, identifier, pr_mr_id, reviews_by_commit)
    return jsonify({"vcs_type": vcs_type, "identifier": identifier, "pr_mr_id": pr_mr_id,
                    "reviews_by_commit": reviews_by_commit, **enriched}), 200


def _parse_github_identifier(identifier: str) -> Optional[Tuple[str, str]]:
    if not identifier or "/" not in identifier:
        return None
    owner, repo = identifier.split("/", 1)
    if not owner or not repo:
        return None
    return owner, repo


def _base_vcs(vcs_type: str) -> str:
    return (vcs_type or "").split("_", 1)[0].lower()


@bp.route("/api/rag/call_graph", methods=["POST"])
@require_admin_key
def api_rag_call_graph():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    data = request.get_json(silent=True) or {}
    vcs_type = str(data.get("vcs_type") or "")
    identifier = str(data.get("identifier") or "")
    pr_mr_id = str(data.get("pr_mr_id") or "")
    opts: Dict[str, Any] = data.get("options") or {}

    if not vcs_type or not identifier or not pr_mr_id:
        return jsonify({"error": "Missing fields: vcs_type, identifier, pr_mr_id"}), 400

    base = _base_vcs(vcs_type)
    parser = str(opts.get("parser") or "python")
    max_depth = int(opts.get("max_depth") or 3)
    cross_file = bool(opts.get("cross_file") or False)

    structured_changes = None
    rag_sources = ["code_context"]

    try:
        if base == "github":
            parsed = _parse_github_identifier(identifier)
            if not parsed:
                return jsonify({"error": "Invalid GitHub identifier. Expected owner/repo"}), 400
            owner, repo = parsed
            cfg = github_repo_configs.get(identifier) or {}
            token = cfg.get("token")
            if not token:
                return jsonify({"error": "GitHub token not configured for this repo"}), 400
            structured_changes = get_github_pr_changes(owner, repo, pr_mr_id, token) or {}
        elif base == "gitlab":
            cfg = gitlab_project_configs.get(str(identifier)) or {}
            token = cfg.get("token")
            if not token:
                return jsonify({"error": "GitLab token not configured for this project"}), 400
            structured_changes, _position = get_gitlab_mr_changes(identifier, pr_mr_id, token)
            structured_changes = structured_changes or {}
        else:
            return jsonify({"error": f"Unsupported vcs_type: {vcs_type}"}), 400
    except Exception as e:
        logger.exception("RAG call graph: failed to fetch diffs")
        return jsonify({"error": f"Failed to fetch diff: {e}"}), 500

    graph = rag_call_graph.build_call_graph_from_structured_changes(
        structured_changes,
        max_depth=max_depth,
        cross_file=cross_file,
        parser=parser,
    )
    app_log.add_event("rag.call_graph", "Built call graph", {
        "vcs_type": vcs_type,
        "identifier": identifier,
        "pr_mr_id": pr_mr_id,
        "params": graph.get("params"),
        "sources": graph.get("sources"),
    })
    return jsonify({"graph": graph, "structured_files": sorted(list(structured_changes.keys())), "rag_sources": rag_sources}), 200


@bp.route("/api/rag/status", methods=["GET"])
@require_admin_key
def api_rag_status():
    project_key = str(request.args.get("project_key") or "").strip()
    if not project_key:
        return jsonify({"error": "Missing query param: project_key"}), 400
    return jsonify(rag_service.index_status(project_key)), 200


@bp.route("/api/rag/reindex", methods=["POST"])
@require_admin_key
def api_rag_reindex():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    data = request.get_json(silent=True) or {}
    project_key = str(data.get("project_key") or "").strip()
    sources = data.get("sources") or []
    if not project_key:
        return jsonify({"error": "Missing field: project_key"}), 400
    if not isinstance(sources, list) or not sources:
        sources = ["project_docs", "dependency_docs"]

    rebuilt = {}
    for src in sources:
        try:
            idx = rag_service.rebuild_index(project_key, str(src))
            rebuilt[str(src)] = {"documents": len((idx or {}).get("documents") or []), "created_at": (idx or {}).get("created_at")}
        except Exception as e:
            rebuilt[str(src)] = {"error": str(e)}
    app_log.add_event("rag.reindex", "Rebuilt RAG indexes", {"project_key": project_key, "sources": sources})
    return jsonify({"project_key": project_key, "rebuilt": rebuilt}), 200


@bp.route("/api/rag/search", methods=["POST"])
@require_admin_key
def api_rag_search():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    data = request.get_json(silent=True) or {}
    project_key = str(data.get("project_key") or "").strip()
    query = str(data.get("query") or "").strip()
    sources = data.get("sources") or []
    top_k = int(data.get("top_k") or 5)
    if not project_key or not query:
        return jsonify({"error": "Missing fields: project_key, query"}), 400
    if not isinstance(sources, list) or not sources:
        sources = ["project_docs", "dependency_docs"]
    hits = rag_service.retrieve(project_key, query, sources=[str(s) for s in sources], top_k=top_k)

    out = []
    for h in hits:
        doc = (h.get("doc") or {})
        meta = doc.get("meta") or {}
        out.append({
            "score": h.get("score"),
            "source": h.get("source"),
            "path": meta.get("path"),
            "snippet": (doc.get("text") or "")[:500],
        })
    app_log.add_event("rag.search", "RAG search", {"project_key": project_key, "sources": sources})
    return jsonify({"project_key": project_key, "hits": out}), 200
