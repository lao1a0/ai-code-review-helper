import json
import logging
import os
from datetime import datetime
from typing import Optional

from db.models import ReviewResult, db

logger = logging.getLogger(__name__)

# In-memory webhook configs (no DB persistence; only review results are stored)
def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def init_postgres_config():
    """Initialize PostgreSQL storage for review results."""
    try:
        db.create_all()
        logger.info("PostgreSQL review results initialized.")
    except Exception as e:
        logger.critical("Failed to initialize PostgreSQL review results: %s", e)
        raise ValueError(e)


def save_review_results(vcs_type: str, identifier: str, pr_mr_id: str, commit_sha: str,
                        review_json_string: str, project_name: str = None, branch: str = None,
                        created_at: str = None, project_url: str = None):
    """Save AI review results to PostgreSQL."""
    if not commit_sha:
        logger.warning("Empty commit_sha for %s:%s:%s. Skip save.", vcs_type, identifier, pr_mr_id)
        return

    review_time = _parse_iso_datetime(created_at)
    try:
        existing = ReviewResult.query.filter_by(
            project_type=vcs_type,
            project=identifier,
            pr_mr_id=str(pr_mr_id),
            commit_sha=commit_sha,
        ).first()

        if existing:
            existing.review_content = review_json_string
            existing.branch = branch
            existing.date = review_time
            existing.updated_at = datetime.utcnow()
        else:
            review_result = ReviewResult(
                project_type=vcs_type,
                project=identifier,
                pr_mr_id=str(pr_mr_id),
                commit_sha=commit_sha,
                review_content=review_json_string,
                branch=branch,
                date=review_time,
            )
            db.session.add(review_result)

        db.session.commit()
        logger.info("Saved review results for %s %s #%s (commit: %s).",
                    vcs_type, identifier, pr_mr_id, commit_sha)
    except Exception as e:
        db.session.rollback()
        logger.error("Failed to save review results (commit: %s): %s", commit_sha, e)


def get_review_results(vcs_type: str, identifier: str, pr_mr_id: str, commit_sha: str = None):
    """Read review results from PostgreSQL."""
    try:
        if commit_sha:
            result = ReviewResult.query.filter_by(
                project_type=vcs_type,
                project=identifier,
                pr_mr_id=str(pr_mr_id),
                commit_sha=commit_sha,
            ).first()
            if result:
                return json.loads(result.review_content)
            return None

        results = ReviewResult.query.filter_by(
            project_type=vcs_type,
            project=identifier,
            pr_mr_id=str(pr_mr_id),
        ).all()

        decoded_results = {}
        for result in results:
            if result.commit_sha not in decoded_results:
                try:
                    decoded_results[result.commit_sha] = json.loads(result.review_content)
                except json.JSONDecodeError as e:
                    logger.error("Invalid review JSON (commit: %s): %s", result.commit_sha, e)

        return {"commits": decoded_results}
    except Exception as e:
        logger.error("Failed to read review results: %s", e)
        return None if commit_sha else {}


def get_all_reviewed_prs_mrs_keys():
    """List all PR/MR keys with stored review results."""
    try:
        results = db.session.query(
            ReviewResult.project_type,
            ReviewResult.project,
            ReviewResult.pr_mr_id,
            db.func.max(ReviewResult.branch).label("branch"),
            db.func.max(ReviewResult.created_at).label("created_at"),
            db.func.max(ReviewResult.commit_sha).label("last_commit_sha"),
        ).group_by(
            ReviewResult.project_type,
            ReviewResult.project,
            ReviewResult.pr_mr_id,
        ).all()

        identifiers = []
        for result in results:
            vcs_type = result.project_type
            identifier = result.project
            pr_mr_id = result.pr_mr_id
            branch = result.branch
            created_at = result.created_at.isoformat() if result.created_at else ""
            last_commit_sha = result.last_commit_sha

            if vcs_type == "github_general":
                display_vcs_type_prefix = "GITHUB (General)"
            elif vcs_type == "gitlab_general":
                display_vcs_type_prefix = "GITLAB (General)"
            elif vcs_type == "github":
                display_vcs_type_prefix = "GITHUB (Detailed)"
            elif vcs_type == "gitlab":
                display_vcs_type_prefix = "GITLAB (Detailed)"
            elif vcs_type == "github_push":
                display_vcs_type_prefix = "GITHUB (Push Audit)"
            elif vcs_type == "gitlab_push":
                display_vcs_type_prefix = "GITLAB (Push Audit)"
            else:
                display_vcs_type_prefix = (vcs_type or "unknown").upper()

            identifiers.append({
                "vcs_type": vcs_type,
                "identifier": identifier,
                "pr_mr_id": pr_mr_id,
                "display_name": f"{display_vcs_type_prefix}: {identifier} #{pr_mr_id}",
                "created_at": created_at,
                "branch": branch or "",
                "last_commit_sha": last_commit_sha or "",
                "project_name": identifier,
            })

        return identifiers
    except Exception as e:
        logger.error("Failed to list reviewed PR/MR keys: %s", e)
        return []
