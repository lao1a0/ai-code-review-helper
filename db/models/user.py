import uuid
from datetime import datetime

from flask_login import UserMixin
from sqlalchemy.dialects.postgresql import UUID
from werkzeug.security import check_password_hash, generate_password_hash

from db.models import db, login_manager


class User(UserMixin, db.Model):
    """User model."""

    __tablename__ = "users"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = db.Column(db.String(80), unique=True, nullable=False)
    nickname = db.Column(db.String(100), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    llm_type = db.Column(db.String(255), nullable=True)
    llm_token = db.Column(db.String(255), nullable=True)
    llm_url = db.Column(db.String(255), nullable=True)
    gitlab_token = db.Column(db.String(255), nullable=True)
    github_token = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    gitlab_projects = db.relationship("GitLabProject", backref="user", lazy="dynamic")
    github_projects = db.relationship("GitHubProject", backref="user", lazy="dynamic")

    def set_password(self, password: str) -> None:
        """Set password hash."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Check password hash."""
        return check_password_hash(self.password_hash, password)

    def to_dict(self, include_sensitive: bool = False):
        """Serialize user fields."""
        payload = {
            "id": str(self.id) if self.id else None,
            "username": self.username,
            "nickname": self.nickname,
            "llm_type": self.llm_type,
            "llm_url": self.llm_url,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_sensitive:
            payload.update({
                "llm_token": self.llm_token,
                "gitlab_token": self.gitlab_token,
                "github_token": self.github_token,
            })
        return payload


@login_manager.user_loader
def load_user(user_id):
    """Flask-Login user loader."""
    return User.query.get(str(user_id))
