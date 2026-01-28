import uuid
from datetime import datetime

from sqlalchemy.dialects.postgresql import UUID

from db.models import db


class GitLabProject(db.Model):
    """GitLab project model."""

    __tablename__ = "gitlab_projects"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"), nullable=False)

    token = db.Column(db.String(255), nullable=False)
    secret = db.Column(db.String(255), nullable=True)
    project_id = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(500), nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    reviews = db.relationship("GitLabReview", backref="project", lazy="dynamic", cascade="all, delete-orphan")

    def to_dict(self):
        """Serialize project fields."""
        return {
            "id": str(self.id) if self.id else None,
            "user_id": str(self.user_id) if self.user_id else None,
            "token": self.token,
            "secret": self.secret,
            "project_id": self.project_id,
            "url": self.url,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class GitHubProject(db.Model):
    """GitHub project model."""

    __tablename__ = "github_projects"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"), nullable=False)

    token = db.Column(db.String(255), nullable=False)
    secret = db.Column(db.String(255), nullable=True)
    repo = db.Column(db.String(200), nullable=False)
    owner = db.Column(db.String(100), nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    reviews = db.relationship("GitHubReview", backref="project", lazy="dynamic", cascade="all, delete-orphan")

    def to_dict(self):
        """Serialize project fields."""
        return {
            "id": str(self.id) if self.id else None,
            "user_id": str(self.user_id) if self.user_id else None,
            "token": self.token,
            "secret": self.secret,
            "repo": self.repo,
            "owner": self.owner,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
