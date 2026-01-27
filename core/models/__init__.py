"""
Core models package
"""
import uuid
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()

# Import all models
from .user import User
from .project import Project
from .review import Review


@login_manager.user_loader
def load_user(user_id):
    """Load a user for flask-login from the stored session id."""
    try:
        return User.query.get(uuid.UUID(user_id))
    except (ValueError, TypeError):
        return None

__all__ = ['db', 'login_manager', 'User', 'Project', 'Review']
