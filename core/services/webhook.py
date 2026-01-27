"""
Webhook service for handling GitHub/GitLab webhooks
"""
import logging
import json
from typing import Dict, Any, Optional
from core.models import Project, db
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

# Global instance
_webhook_service = None

def get_webhook_service() -> WebhookService:
    """Get global webhook service instance"""
    global _webhook_service
    if _webhook_service is None:
        _webhook_service = WebhookService()
    return _webhook_service
