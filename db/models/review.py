import uuid
from datetime import datetime

from sqlalchemy.dialects.postgresql import UUID

from db.models import db


class GitLabReview(db.Model):
    """GitLab review model."""

    __tablename__ = "gitlab_reviews"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = db.Column(UUID(as_uuid=True), db.ForeignKey("gitlab_projects.id"), nullable=False)

    ai_name = db.Column(db.String(100), nullable=True)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    review_content = db.Column(db.Text, nullable=True)
    quality_score = db.Column(db.Float, nullable=True)

    commit_sha = db.Column(db.String(40), nullable=False)
    pr_mr_id = db.Column(db.String(50), nullable=False)
    branch = db.Column(db.String(200), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        """Serialize review fields."""
        return {
            "id": str(self.id) if self.id else None,
            "project_id": str(self.project_id) if self.project_id else None,
            "ai_name": self.ai_name,
            "date": self.date.isoformat() if self.date else None,
            "review_content": self.review_content,
            "quality_score": self.quality_score,
            "commit_sha": self.commit_sha,
            "pr_mr_id": self.pr_mr_id,
            "branch": self.branch,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class GitHubReview(db.Model):
    """GitHub review model."""

    __tablename__ = "github_reviews"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = db.Column(UUID(as_uuid=True), db.ForeignKey("github_projects.id"), nullable=False)

    ai_name = db.Column(db.String(100), nullable=True)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    review_content = db.Column(db.Text, nullable=True)
    quality_score = db.Column(db.Float, nullable=True)

    commit_sha = db.Column(db.String(40), nullable=False)
    pr_mr_id = db.Column(db.String(50), nullable=False)
    branch = db.Column(db.String(200), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        """Serialize review fields."""
        return {
            "id": str(self.id) if self.id else None,
            "project_id": str(self.project_id) if self.project_id else None,
            "ai_name": self.ai_name,
            "date": self.date.isoformat() if self.date else None,
            "review_content": self.review_content,
            "quality_score": self.quality_score,
            "commit_sha": self.commit_sha,
            "pr_mr_id": self.pr_mr_id,
            "branch": self.branch,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
