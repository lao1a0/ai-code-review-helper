"""
Webhook service for handling GitHub/GitLab webhooks
"""
import logging
import json
import os
from typing import Dict, Any, Optional, List, Tuple
import requests
from core.models import Project, Review, db
from .review import get_review_service

logger = logging.getLogger(__name__)

class WebhookService:
    """Webhook service for processing GitHub/GitLab events"""
    
    def __init__(self):
        self.review_service = get_review_service()
    
    def process_github_webhook(self, payload: Dict[str, Any]) -> bool:
        """Process GitHub webhook payload"""
        try:
            event_type = payload.get('action')
            if event_type != 'opened' and event_type != 'synchronize':
                logger.info(f"Skipping GitHub event: {event_type}")
                return True
            
            # Extract PR information
            pull_request = payload.get('pull_request', {})
            if not pull_request:
                logger.error("No pull request data in GitHub webhook")
                return False
            
            repo = payload.get('repository', {})
            project_key = f"github:{repo.get('full_name', '')}"
            
            # Find or create project
            project = self._get_or_create_project(
                name=repo.get('name', ''),
                platform='github',
                repo_url=repo.get('html_url', ''),
                project_key=project_key
            )
            
            if not project:
                return False
            
            files = self._fetch_github_files(
                full_name=repo.get('full_name', ''),
                pr_number=str(pull_request.get('number', ''))
            )

            # Create review
            review = self.review_service.create_review(
                project_id=str(project.id),
                platform='github',
                commit_sha=pull_request.get('head', {}).get('sha', ''),
                pr_mr_id=str(pull_request.get('number', '')),
                branch=pull_request.get('head', {}).get('ref', ''),
                ai_name='AI-GitHub'
            )
            
            if review:
                if files:
                    self.review_service.perform_review_for_files(str(review.id), files)
                    self._post_github_review(
                        review_id=str(review.id),
                        repo_full_name=repo.get('full_name', ''),
                        pr_number=str(pull_request.get('number', '')),
                        commit_sha=pull_request.get('head', {}).get('sha', ''),
                        files=files
                    )
                logger.info(f"GitHub webhook processed successfully: PR #{pull_request.get('number')}")
                return True
            else:
                logger.error("Failed to create review from GitHub webhook")
                return False
                
        except Exception as e:
            logger.error(f"Error processing GitHub webhook: {e}")
            return False
    
    def process_gitlab_webhook(self, payload: Dict[str, Any]) -> bool:
        """Process GitLab webhook payload"""
        try:
            event_type = payload.get('object_kind')
            if event_type != 'merge_request':
                logger.info(f"Skipping GitLab event: {event_type}")
                return True
            
            # Extract MR information
            merge_request = payload.get('object_attributes', {})
            if not merge_request:
                logger.error("No merge request data in GitLab webhook")
                return False
            
            project = payload.get('project', {})
            project_key = f"gitlab:{project.get('path_with_namespace', '')}"
            
            # Find or create project
            project_obj = self._get_or_create_project(
                name=project.get('name', ''),
                platform='gitlab',
                repo_url=project.get('web_url', ''),
                project_key=project_key
            )
            
            if not project_obj:
                return False

            files = self._fetch_gitlab_files(
                project_id=str(project.get('id', '')),
                mr_iid=str(merge_request.get('iid', ''))
            )
            
            # Create review
            review = self.review_service.create_review(
                project_id=str(project_obj.id),
                platform='gitlab',
                commit_sha=merge_request.get('last_commit', {}).get('id', ''),
                pr_mr_id=str(merge_request.get('iid', '')),
                branch=merge_request.get('source_branch', ''),
                ai_name='AI-GitLab'
            )
            
            if review:
                if files:
                    self.review_service.perform_review_for_files(str(review.id), files)
                logger.info(f"GitLab webhook processed successfully: MR #{merge_request.get('iid')}")
                return True
            else:
                logger.error("Failed to create review from GitLab webhook")
                return False
                
        except Exception as e:
            logger.error(f"Error processing GitLab webhook: {e}")
            return False
    
    def _get_or_create_project(self, name: str, platform: str, 
                              repo_url: str, project_key: str) -> Optional[Project]:
        """Get existing project or create new one"""
        try:
            # Try to find existing project
            project = Project.query.filter_by(project_key=project_key).first()
            if project:
                return project
            
            # Create new project
            project = Project()
            project.name = name
            project.platform = platform
            project.repo_url = repo_url
            project.project_key = project_key
            
            db.session.add(project)
            db.session.commit()
            
            logger.info(f"Project created: {project_key}")
            return project
            
        except Exception as e:
            logger.error(f"Failed to get or create project: {e}")
            db.session.rollback()
            return None

    def _fetch_github_files(self, full_name: str, pr_number: str) -> List[Dict[str, Any]]:
        if not full_name or not pr_number:
            return []
        token = os.environ.get('GITHUB_ACCESS_TOKEN', '')
        if not token:
            logger.error("GITHUB_ACCESS_TOKEN not configured")
            return []

        url = f"https://api.github.com/repos/{full_name}/pulls/{pr_number}/files"
        headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github+json'
        }
        try:
            resp = requests.get(url, headers=headers, timeout=20)
            resp.raise_for_status()
            items = resp.json() or []
            files = []
            for it in items:
                files.append({
                    'file_path': it.get('filename', ''),
                    'status': it.get('status', 'modified'),
                    'diff_text': it.get('patch', '') or '',
                    'old_content': None
                })
            return files
        except Exception as e:
            logger.error(f"Failed to fetch GitHub files: {e}")
            return []

    def _post_github_review(self, review_id: str, repo_full_name: str, pr_number: str,
                            commit_sha: str, files: List[Dict[str, Any]]) -> None:
        if not repo_full_name or not pr_number or not commit_sha:
            return
        token = os.environ.get('GITHUB_ACCESS_TOKEN', '')
        if not token:
            logger.error("GITHUB_ACCESS_TOKEN not configured")
            return

        review = Review.query.get(review_id)
        if not review or not review.review_content:
            logger.error("No review content available for GitHub comment")
            return

        try:
            review_items = json.loads(review.review_content)
        except Exception as exc:
            logger.error(f"Failed to parse review content: {exc}")
            return

        file_map = {f.get('file_path'): f for f in files}
        comments = []
        for item in review_items:
            path = item.get('file') or ''
            body = item.get('review') or ''
            if not path or not body:
                continue
            patch = (file_map.get(path) or {}).get('diff_text', '')
            position = self._first_comment_position(patch)
            if position is None:
                continue
            comments.append({
                'path': path,
                'position': position,
                'body': body
            })

        summary = self._build_review_summary(review_items)
        payload = {
            'body': summary,
            'event': 'COMMENT'
        }
        if comments:
            payload['commit_id'] = commit_sha
            payload['comments'] = comments

        url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}/reviews"
        headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github+json'
        }
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=20)
            if resp.status_code == 422 and comments and "Position could not be resolved" in resp.text:
                logger.warning("GitHub review comment positions invalid, retrying summary only")
                resp = requests.post(url, headers=headers, json={'body': summary, 'event': 'COMMENT'}, timeout=20)
            if resp.status_code >= 400:
                logger.error(f"GitHub review failed: {resp.status_code} {resp.text}")
                resp.raise_for_status()
            logger.info(f"GitHub review posted: PR #{pr_number} (comments: {len(comments)})")
            self._post_github_file_comments(repo_full_name, pr_number, review_items)
        except Exception as exc:
            logger.error(f"Failed to post GitHub review: {exc}")

    def _post_github_file_comments(self, repo_full_name: str, pr_number: str,
                                   review_items: List[Dict[str, Any]]) -> None:
        token = os.environ.get('GITHUB_ACCESS_TOKEN', '')
        if not token:
            logger.error("GITHUB_ACCESS_TOKEN not configured")
            return
        headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github+json'
        }
        url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
        for item in review_items:
            path = item.get('file') or ''
            body = (item.get('review') or '').strip()
            if not path or not body:
                continue
            comment_body = f"File: {path}\n\n{body}"
            try:
                resp = requests.post(url, headers=headers, json={'body': comment_body}, timeout=20)
                if resp.status_code >= 400:
                    logger.error(f"GitHub file comment failed: {resp.status_code} {resp.text}")
            except Exception as exc:
                logger.error(f"Failed to post GitHub file comment: {exc}")

    def _build_review_summary(self, review_items: List[Dict[str, Any]]) -> str:
        if not review_items:
            return "AI 代码审计：未发现需要评论的问题。"
        lines = ["AI 代码审计摘要：", ""]
        for item in review_items:
            path = item.get('file') or ''
            review = (item.get('review') or '').strip()
            if not path or not review:
                continue
            brief = review.splitlines()[0] if review else ''
            lines.append(f"- {path}: {brief}")
        return "\n".join(lines).strip()

    def _first_comment_position(self, patch: str) -> Optional[int]:
        if not patch:
            return None
        position = 0
        first_context = None
        for line in patch.splitlines():
            if line.startswith(('@@', ' ', '+', '-')):
                position += 1
                if line.startswith('+') and not line.startswith('+++'):
                    return position
                if first_context is None and line.startswith(' '):
                    first_context = position
        return first_context if first_context is not None else (position if position > 0 else None)

    def _fetch_gitlab_files(self, project_id: str, mr_iid: str) -> List[Dict[str, Any]]:
        if not project_id or not mr_iid:
            return []
        token = os.environ.get('GITLAB_ACCESS_TOKEN', '')
        base_url = os.environ.get('GITLAB_INSTANCE_URL', '').rstrip('/')
        if not token or not base_url:
            logger.error("GITLAB_ACCESS_TOKEN or GITLAB_INSTANCE_URL not configured")
            return []

        url = f"{base_url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/changes"
        headers = {
            'PRIVATE-TOKEN': token
        }
        try:
            resp = requests.get(url, headers=headers, timeout=20)
            resp.raise_for_status()
            data = resp.json() or {}
            files = []
            for it in data.get('changes', []) or []:
                files.append({
                    'file_path': it.get('new_path', ''),
                    'status': 'modified',
                    'diff_text': it.get('diff', '') or '',
                    'old_content': None
                })
            return files
        except Exception as e:
            logger.error(f"Failed to fetch GitLab files: {e}")
            return []

# Global instance
_webhook_service = None

def get_webhook_service() -> WebhookService:
    """Get global webhook service instance"""
    global _webhook_service
    if _webhook_service is None:
        _webhook_service = WebhookService()
    return _webhook_service
