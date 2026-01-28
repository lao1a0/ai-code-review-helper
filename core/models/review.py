"""
Unified review model for code reviews
"""
import uuid
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID
from . import db

class Review(db.Model):
    """Unified review model for all platforms"""
    
    __tablename__ = 'reviews'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = db.Column(UUID(as_uuid=True), db.ForeignKey('projects.id'), nullable=False)
    
    # Review metadata
    ai_name = db.Column(db.String(100), nullable=True)
    review_date = db.Column(db.DateTime, default=datetime.utcnow)
    review_content = db.Column(db.Text, nullable=True)
    quality_score = db.Column(db.Float, nullable=True)
    
    # Git information
    commit_sha = db.Column(db.String(40), nullable=False)
    pr_mr_id = db.Column(db.String(50), nullable=False)
    branch = db.Column(db.String(200), nullable=True)
    
    # Platform and status
    platform = db.Column(db.String(50), nullable=False)  # 'github' or 'gitlab'
    status = db.Column(db.String(50), default='pending')  # pending, completed, failed
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Review {self.platform}:{self.pr_mr_id}>'
    
    def to_dict(self):
        """Convert review to dictionary"""
        return {
            'id': str(self.id),
            'project_id': str(self.project_id),
            'ai_name': self.ai_name,
            'review_date': self.review_date.isoformat() if self.review_date else None,
            'review_content': self.review_content,
            'quality_score': self.quality_score,
            'commit_sha': self.commit_sha,
            'pr_mr_id': self.pr_mr_id,
            'branch': self.branch,
            'platform': self.platform,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
