"""
Review service for code review operations
"""
import json
import logging
from typing import Dict, Any, List, Optional
from core.models import Review, Project, db
from .llm import get_llm_service

logger = logging.getLogger(__name__)

class ReviewService:
    """Unified review service"""
    
    def __init__(self):
        self.llm_service = get_llm_service()
    
    def create_review(self, project_id: str, platform: str, commit_sha: str, 
                     pr_mr_id: str, branch: Optional[str] = None, ai_name: Optional[str] = None) -> Optional[Review]:
        """Create a new review record"""
        try:
            review = Review()
            review.project_id = project_id
            review.platform = platform
            review.commit_sha = commit_sha
            review.pr_mr_id = pr_mr_id
            review.branch = branch or ""
            review.ai_name = ai_name or f"AI-{platform}"
            review.status = 'pending'
            
            db.session.add(review)
            db.session.commit()
            
            logger.info(f"Review created: {platform}:{pr_mr_id}")
            return review
            
        except Exception as e:
            logger.error(f"Failed to create review: {e}")
            db.session.rollback()
            return None
    
    def perform_general_review(self, review_id: str, file_data: Dict[str, Any]) -> bool:
        """Perform general code review"""
        try:
            review = Review.query.get(review_id)
            if not review:
                logger.error(f"Review not found: {review_id}")
                return False
            
            # Perform LLM review
            review_content = self.llm_service.get_general_review(file_data)
            
            # Update review
            review.review_content = review_content
            review.status = 'completed'
            db.session.commit()
            
            logger.info(f"General review completed for review {review_id}")
            return True
            
        except Exception as e:
            logger.error(f"General review failed: {e}")
            self._mark_review_failed(review_id)
            return False

    def perform_review_for_files(self, review_id: str, files: List[Dict[str, Any]]) -> bool:
        """Perform review for a list of files and store aggregated results."""
        try:
            review = Review.query.get(review_id)
            if not review:
                logger.error(f"Review not found: {review_id}")
                return False

            results = []
            for file_data in files:
                content = self.llm_service.get_general_review(file_data)
                if content:
                    results.append({
                        'file': file_data.get('file_path', ''),
                        'review': content
                    })

            review.review_content = json.dumps(results, ensure_ascii=False)
            review.status = 'completed'
            db.session.commit()

            logger.info(f"Review completed for {review_id} with {len(results)} file(s)")
            return True
        except Exception as e:
            logger.error(f"Review failed: {e}")
            self._mark_review_failed(review_id)
            return False
    
    def perform_detailed_review(self, review_id: str, file_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Perform detailed code review"""
        try:
            review = Review.query.get(review_id)
            if not review:
                logger.error(f"Review not found: {review_id}")
                return []
            
            # Perform LLM review
            review_items = self.llm_service.get_detailed_review(file_data)
            
            # Update review
            review.review_content = str(review_items)
            review.status = 'completed'
            db.session.commit()
            
            logger.info(f"Detailed review completed for review {review_id}")
            return review_items
            
        except Exception as e:
            logger.error(f"Detailed review failed: {e}")
            self._mark_review_failed(review_id)
            return []
    
    def get_review_by_id(self, review_id: str) -> Optional[Review]:
        """Get review by ID"""
        try:
            return Review.query.get(review_id)
        except Exception as e:
            logger.error(f"Error getting review: {e}")
            return None
    
    def get_reviews_by_project(self, project_id: str, limit: int = 50) -> List[Review]:
        """Get reviews by project"""
        try:
            return Review.query.filter_by(project_id=project_id)\
                              .order_by(Review.created_at.desc())\
                              .limit(limit).all()
        except Exception as e:
            logger.error(f"Error getting reviews by project: {e}")
            return []
    
    def get_reviews_by_platform(self, platform: str, limit: int = 50) -> List[Review]:
        """Get reviews by platform"""
        try:
            return Review.query.filter_by(platform=platform)\
                              .order_by(Review.created_at.desc())\
                              .limit(limit).all()
        except Exception as e:
            logger.error(f"Error getting reviews by platform: {e}")
            return []
    
    def _mark_review_failed(self, review_id: str):
        """Mark review as failed"""
        try:
            review = Review.query.get(review_id)
            if review:
                review.status = 'failed'
                db.session.commit()
        except Exception as e:
            logger.error(f"Failed to mark review as failed: {e}")

# Global instance
_review_service = None

def get_review_service() -> ReviewService:
    """Get global review service instance"""
    global _review_service
    if _review_service is None:
        _review_service = ReviewService()
    return _review_service
