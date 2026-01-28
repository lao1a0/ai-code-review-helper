from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()

# 导入所有模型
from db.models.user import User
from db.models.project import GitLabProject, GitHubProject
from db.models.review import GitLabReview, GitHubReview
from db.models.review_result import ReviewResult
from db.models.config import Config

__all__ = ['db', 'login_manager', 'User', 'GitLabProject', 'GitHubProject', 'GitLabReview', 'GitHubReview', 'ReviewResult', 'Config']
