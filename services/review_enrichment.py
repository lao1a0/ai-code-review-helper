import re
from typing import Any, Dict, List, Optional, Set, Tuple

from services import settings_store


_SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
    "UNKNOWN": 0,
}


def _normalize_severity(value: Any) -> str:
    if not value:
        return "UNKNOWN"
    s = str(value).strip().upper()
    if s in _SEVERITY_ORDER:
        return s
    # Common variants
    if s in {"WARN", "WARNING"}:
        return "LOW"
    if s in {"SEVERE"}:
        return "HIGH"
    return "UNKNOWN"


def compute_risk_level(reviews_by_commit: Dict[str, Any]) -> str:
    max_level = 0
    for _, items in (reviews_by_commit or {}).items():
        if not isinstance(items, list):
            continue
        for it in items:
            if not isinstance(it, dict):
                continue
            sev = _normalize_severity(it.get("severity"))
            max_level = max(max_level, _SEVERITY_ORDER.get(sev, 0))
    inv = {v: k for k, v in _SEVERITY_ORDER.items()}
    return inv.get(max_level, "UNKNOWN")


def extract_changed_files(reviews_by_commit: Dict[str, Any]) -> List[str]:
    files: Set[str] = set()
    for _, items in (reviews_by_commit or {}).items():
        if not isinstance(items, list):
            continue
        for it in items:
            if isinstance(it, dict) and it.get("file"):
                files.add(str(it["file"]))
    return sorted(files)


def _text_blob(reviews_by_commit: Dict[str, Any]) -> str:
    parts = []
    for _, items in (reviews_by_commit or {}).items():
        if not isinstance(items, list):
            continue
        for it in items:
            if not isinstance(it, dict):
                continue
            for k in ("category", "analysis", "suggestion", "file"):
                v = it.get(k)
                if v:
                    parts.append(str(v))
    return "\n".join(parts).lower()


def infer_skill_hits(
    vcs_type: str,
    identifier: str,
    pr_mr_id: str,
    reviews_by_commit: Dict[str, Any],
    configured_skills: Optional[List[str]] = None,
) -> List[str]:
    """
    Heuristic-only. Real skill hits should come from the model output.
    """
    blob = _text_blob(reviews_by_commit)
    enabled = configured_skills or []

    # If no explicit config, fall back to all known core skills.
    if not enabled:
        enabled = [
            "secure-code-review",
            "performance-review",
            "style-and-consistency",
            "test-coverage-review",
            "architecture-consistency",
        ]

    checks: List[Tuple[str, List[str]]] = [
        ("secure-code-review", ["sql", "xss", "csrf", "ssrf", "idor", "auth", "permission", "inject", "漏洞", "越权", "鉴权", "token", "secret"]),
        ("performance-review", ["performance", "slow", "n+1", "cache", "timeout", "latency", "性能", "耗时", "o(n", "o(n^2"]),
        ("style-and-consistency", ["style", "naming", "consistency", "format", "lint", "readability", "规范", "一致性", "可读"]),
        ("test-coverage-review", ["test", "coverage", "unit", "integration", "mock", "单测", "用例", "测试"]),
        ("architecture-consistency", ["architecture", "layer", "coupling", "dependency", "模块", "分层", "架构", "边界"]),
    ]

    hits = []
    for name, kws in checks:
        if name not in enabled:
            continue
        if any(k in blob for k in kws):
            hits.append(name)

    return hits


def project_key_from_review(vcs_type: str, identifier: str) -> Optional[str]:
    if not vcs_type or not identifier:
        return None
    base = vcs_type.split("_", 1)[0].lower()  # github/gitlab/github_push/...
    if base == "github":
        return f"github:{identifier}"
    if base == "gitlab":
        return f"gitlab:{identifier}"
    return None


def get_project_configured_skills(project_key: Optional[str]) -> List[str]:
    if not project_key:
        return []
    settings = settings_store.get_project_settings(project_key)
    skills = settings.get("skills_enabled") or []
    if isinstance(skills, list):
        return [str(x) for x in skills]
    return []


def get_project_rag_sources(project_key: Optional[str]) -> List[str]:
    if not project_key:
        return []
    settings = settings_store.get_project_settings(project_key)
    rag = settings.get("rag") or {}
    if not rag.get("enabled"):
        return []
    sources = rag.get("sources") or {}
    out = []
    if sources.get("code", True):
        out.append("code_context")
    if sources.get("docs"):
        out.append("project_docs")
    if sources.get("deps"):
        out.append("dependency_docs")
    return out


def summarize_review(vcs_type: str, identifier: str, pr_mr_id: str, reviews_by_commit: Dict[str, Any]) -> Dict[str, Any]:
    project_key = project_key_from_review(vcs_type, identifier)
    configured_skills = get_project_configured_skills(project_key)
    return {
        "risk_level": compute_risk_level(reviews_by_commit),
        "files": extract_changed_files(reviews_by_commit),
        "skill_hits": infer_skill_hits(vcs_type, identifier, pr_mr_id, reviews_by_commit, configured_skills=configured_skills),
        "skills_configured": configured_skills,
        "rag_sources": get_project_rag_sources(project_key),
        "project_key": project_key,
    }
