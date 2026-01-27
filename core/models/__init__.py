"""
Core models package
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()

# Import all models
from .user import User
from .project import Project
from .review import Review

__all__ = ['db', 'login_manager', 'User', 'Project', 'Review']
