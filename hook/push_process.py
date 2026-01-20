import json
import logging
from typing import Optional

from config.core_config import app_configs, gitlab_project_configs, mark_commit_as_processed, github_repo_configs
from hook.helpers import _save_review_results_and_log
from services.llm_service import get_openai_client, get_openai_detailed_review_for_file
from services.notification_service import send_notifications
from services.vcs_service import (get_github_push_changes, get_gitlab_push_changes, add_github_commit_comment,
                                  add_gitlab_commit_comment, )

logger = logging.getLogger(__name__)

_PUSH_AUDIT_IGNORED_EXTS = {  # docs / plain text (usually low-value for vuln review)
    ".md", ".markdown", ".mdx", ".rst", ".adoc", ".asciidoc", ".txt", ".text", ".csv", ".tsv", ".log",
    # media / binaries
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".tiff", ".mp3", ".wav", ".flac", ".mp4", ".mov", ".avi",
    ".mkv", ".pdf", ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".woff", ".woff2", ".ttf", ".otf", ".exe", ".dll",
    ".so", ".dylib", }

_PUSH_AUDIT_IGNORED_BASENAMES = {"readme", "license", "notice", "changelog", "code_of_conduct", }

_PUSH_AUDIT_IGNORED_DIR_PARTS = {"docs", "doc", "images", "img", "assets", "static", "public", "media", }


def _looks_like_binary_or_unhelpful_diff(file_data: dict) -> bool:
    changes = file_data.get("changes") or []
    if not changes:
        return True
    # placeholder-only deletions (we don't have real diff context to review)
    if (len(changes) == 1 and changes[0].get("type") == "delete" and changes[0].get("old_line") == 0 and (
            changes[0].get("content") or "").strip() in {"文件已删除", "binary", "Binary files differ"}):
        return True

    context_old = ((file_data.get("context") or {}).get("old") or "")
    context_new = ((file_data.get("context") or {}).get("new") or "")
    combined = f"{context_old}\n{context_new}\n" + "\n".join((c.get("content") or "") for c in changes[:50])
    markers = ["GIT binary patch", "Binary files", "binary files", "image/png", "application/octet-stream"]
    return any(m in combined for m in markers)


def _should_skip_push_audit_file(file_path: str, file_data: dict) -> Optional[str]:
    if not file_path:
        return "missing_path"
    path_lower = file_path.lower()
    basename = path_lower.rsplit("/", 1)[-1]
    name_only = basename.split(".", 1)[0]
    ext = ""
    if "." in basename:
        ext = "." + basename.rsplit(".", 1)[-1]

    if name_only in _PUSH_AUDIT_IGNORED_BASENAMES:
        return "ignored_basename"

    parts = [p for p in path_lower.split("/") if p]
    if any(p in _PUSH_AUDIT_IGNORED_DIR_PARTS for p in parts[:-1]):
        return "ignored_directory"

    if ext in _PUSH_AUDIT_IGNORED_EXTS:
        return "ignored_extension"

    if _looks_like_binary_or_unhelpful_diff(file_data):
        return "binary_or_unhelpful_diff"

    return None


def _make_push_audit_id(ref: str, after_sha: str) -> str:
    safe_ref = (ref or "").replace("/", "_")
    sha_short = (after_sha or "")[:12]
    if safe_ref and sha_short:
        return f"{safe_ref}@{sha_short}"
    if sha_short:
        return sha_short
    return safe_ref or "unknown"


def _build_push_audit_summary_markdown(vcs_label: str, repo_or_project_display: str, ref: str, after_sha: str,
                                       web_url: Optional[str], total_reviews: int, ) -> str:
    sha_short = after_sha[:12] if after_sha else "N/A"
    url_line = f"\n- 链接: {web_url}" if web_url else ""
    return (f"**AI Push 审计结果**\n"
            f"\n- 平台: {vcs_label}"
            f"\n- 目标: {repo_or_project_display}"
            f"\n- 分支: `{ref}`"
            f"\n- 提交: `{sha_short}`"
            f"{url_line}"
            f"\n- 审计建议数: {total_reviews}\n")


def _format_reviews_as_markdown(reviews: list[dict], max_items: int = 10) -> str:
    if not reviews:
        return "\n- 结论: 未发现需要关注的问题。\n"

    lines = ["\n**Top Issues**"]
    for review in reviews[:max_items]:
        file_path = review.get("file", "N/A")
        severity = str(review.get("severity", "N/A")).upper()
        category = review.get("category", "General")
        analysis = (review.get("analysis") or "").strip()
        suggestion = (review.get("suggestion") or "").strip()
        lines.append(f"\n- [{severity}] `{file_path}` ({category})")
        if analysis:
            lines.append(f"  - 分析: {analysis}")
        if suggestion:
            lines.append(f"  - 建议: {suggestion}")
    if len(reviews) > max_items:
        lines.append(f"\n- 其余 {len(reviews) - max_items} 条建议请在管理面板查看。")
    lines.append("")
    return "\n".join(lines)


def _ensure_non_empty_reviews(vcs_label: str, reviews: list[dict]) -> list[dict]:
    if reviews:
        return reviews
    return [{"file": f"Overall {vcs_label} Push Audit", "lines": {"old": None, "new": None}, "category": "General",
             "severity": "INFO", "analysis": "AI Push 审计已完成，未发现需要关注的问题。", "suggestion": "Looks good!", }]


def _process_github_push_payload(access_token: str, owner: str, repo_name: str, repo_full_name: str, ref: str,
                                 audit_id: str, before_sha: str, after_sha: str, created: bool,
                                 default_branch: Optional[str], repo_web_url: Optional[str], ):
    if not app_configs.get("PUSH_AUDIT_ENABLED", True):
        logger.info("GitHub (Push): PUSH_AUDIT_ENABLED=false，跳过审计。")
        return

    max_files = int(app_configs.get("PUSH_AUDIT_MAX_FILES", 20) or 20)
    structured_changes = get_github_push_changes(owner=owner, repo_name=repo_name, before_sha=before_sha,
                                                 after_sha=after_sha, access_token=access_token, created=created,
                                                 default_branch=default_branch, max_files=max_files, )
    if structured_changes is None:
        logger.warning("GitHub (Push): 获取或解析 diff 失败，中止审计。")
        return

    client = get_openai_client()
    if not client:
        logger.error("GitHub (Push): OpenAI 客户端不可用，中止审计。")
        return
    current_model = app_configs.get("OPENAI_MODEL", "gpt-4o")

    all_reviews: list[dict] = []
    skipped: list[tuple[str, str]] = []
    for file_path, file_data in structured_changes.items():
        reason = _should_skip_push_audit_file(file_path, file_data)
        if reason:
            skipped.append((file_path, reason))
            continue
        all_reviews.extend(get_openai_detailed_review_for_file(file_path, file_data, client, current_model))

    all_reviews = _ensure_non_empty_reviews("GitHub", all_reviews)

    _save_review_results_and_log(vcs_type="github_push", identifier=repo_full_name, pr_mr_id=audit_id,
                                 commit_sha=after_sha,
                                 review_json_string=json.dumps(all_reviews, ensure_ascii=False, indent=2),
                                 branch=ref.split('/')[-1])
    mark_commit_as_processed("github_push", repo_full_name, audit_id, after_sha)

    summary = _build_push_audit_summary_markdown(vcs_label="GitHub", repo_or_project_display=repo_full_name, ref=ref,
                                                 after_sha=after_sha, web_url=repo_web_url, total_reviews=len(
            [r for r in all_reviews if "Overall GitHub Push Audit" not in str(r.get("file", ""))]), )
    if skipped:
        summary += f"\n- 已跳过文件数: {len(skipped)}（文档/二进制/无有效diff 等）\n"
    summary += _format_reviews_as_markdown(all_reviews)
    send_notifications(summary)

    if app_configs.get("PUSH_AUDIT_POST_COMMIT_COMMENT", False):
        body = summary
        add_github_commit_comment(owner, repo_name, after_sha, access_token, body)


def _process_gitlab_push_payload(access_token: str, project_id_str: str, ref: str, audit_id: str, before_sha: str,
                                 after_sha: str, project_name: Optional[str], project_web_url: Optional[str],
                                 created: bool, default_branch: Optional[str], ):
    if not app_configs.get("PUSH_AUDIT_ENABLED", True):
        logger.info("GitLab (Push): PUSH_AUDIT_ENABLED=false，跳过审计。")
        return

    project_config = gitlab_project_configs.get(str(project_id_str), {})
    project_specific_instance_url = project_config.get("instance_url")

    max_files = int(app_configs.get("PUSH_AUDIT_MAX_FILES", 20) or 20)
    structured_changes = get_gitlab_push_changes(project_id_str=str(project_id_str), before_sha=before_sha,
                                                 after_sha=after_sha, access_token=access_token,
                                                 instance_url=project_specific_instance_url, created=created,
                                                 default_branch=default_branch, max_files=max_files, )
    if structured_changes is None:
        logger.warning("GitLab (Push): 获取或解析 diff 失败，中止审计。")
        return

    client = get_openai_client()
    if not client:
        logger.error("GitLab (Push): OpenAI 客户端不可用，中止审计。")
        return
    current_model = app_configs.get("OPENAI_MODEL", "gpt-4o")

    all_reviews: list[dict] = []
    skipped: list[tuple[str, str]] = []
    for file_path, file_data in structured_changes.items():
        reason = _should_skip_push_audit_file(file_path, file_data)
        if reason:
            skipped.append((file_path, reason))
            continue
        all_reviews.extend(get_openai_detailed_review_for_file(file_path, file_data, client, current_model))

    all_reviews = _ensure_non_empty_reviews("GitLab", all_reviews)

    _save_review_results_and_log(vcs_type="gitlab_push", identifier=str(project_id_str), pr_mr_id=audit_id,
                                 commit_sha=after_sha,
                                 review_json_string=json.dumps(all_reviews, ensure_ascii=False, indent=2),
                                 project_name_for_gitlab=project_name, branch=ref.split('/')[-1])
    mark_commit_as_processed("gitlab_push", str(project_id_str), audit_id, after_sha)

    display_name = project_name or str(project_id_str)
    summary = _build_push_audit_summary_markdown(vcs_label="GitLab", repo_or_project_display=display_name, ref=ref,
                                                 after_sha=after_sha, web_url=project_web_url, total_reviews=len(
            [r for r in all_reviews if "Overall GitLab Push Audit" not in str(r.get("file", ""))]), )
    if skipped:
        summary += f"\n- 已跳过文件数: {len(skipped)}（文档/二进制/无有效diff 等）\n"
    summary += _format_reviews_as_markdown(all_reviews)
    send_notifications(summary)

    if app_configs.get("PUSH_AUDIT_POST_COMMIT_COMMENT", False):
        note = summary
        add_gitlab_commit_comment(project_id_str=str(project_id_str), commit_sha=after_sha, access_token=access_token,
                                  note=note, instance_url=project_specific_instance_url, )

def get_final_summary_comment_text() -> str:
    """
    生成通用的最终总结评论文本。
    """
    model_name = app_configs.get("OPENAI_MODEL", "gpt-4o")
    return f"本次AI代码审查已完成，审核模型:「{model_name}」 修改意见仅供参考，具体修改请根据实际场景进行调整。"