import logging
from typing import List, Optional, Dict, Any

from db.models import db
from db.models.project import GitLabProject, GitHubProject
from db.models.review import GitLabReview, GitHubReview
from db.models.user import User

logger = logging.getLogger(__name__)


class DatabaseService:
    """数据库服务类，处理所有数据库操作"""

    # 用户相关操作
    @staticmethod
    def create_user(username: str, nickname: str, password: str) -> User:
        """创建新用户"""
        user = User(username=username, nickname=nickname)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return user

    @staticmethod
    def get_user_by_username(username: str) -> Optional[User]:
        """根据用户名获取用户"""
        return User.query.filter_by(username=username).first()

    @staticmethod
    def get_user_by_id(user_id: str) -> Optional[User]:
        """根据ID获取用户"""
        return User.query.get(user_id)

    # GitLab项目相关操作
    @staticmethod
    def create_gitlab_project(user_id: str, token: str, secret: Optional[str], project_id: str,
                              url: str) -> GitLabProject:
        """创建GitLab项目"""
        project = GitLabProject(user_id=user_id, token=token, secret=secret, project_id=project_id, url=url)
        db.session.add(project)
        db.session.commit()
        return project

    @staticmethod
    def get_gitlab_projects_by_user(user_id: str) -> List[GitLabProject]:
        """获取用户的所有GitLab项目"""
        return GitLabProject.query.filter_by(user_id=user_id).all()

    @staticmethod
    def get_gitlab_project_by_id(project_id: str) -> Optional[GitLabProject]:
        """根据ID获取GitLab项目"""
        return GitLabProject.query.get(project_id)

    # GitHub项目相关操作
    @staticmethod
    def create_github_project(user_id: str, token: str, secret: Optional[str], repo: str, owner: str) -> GitHubProject:
        """创建GitHub项目"""
        project = GitHubProject(user_id=user_id, token=token, secret=secret, repo=repo, owner=owner)
        db.session.add(project)
        db.session.commit()
        return project

    @staticmethod
    def get_github_projects_by_user(user_id: str) -> List[GitHubProject]:
        """获取用户的所有GitHub项目"""
        return GitHubProject.query.filter_by(user_id=user_id).all()

    @staticmethod
    def get_github_project_by_id(project_id: str) -> Optional[GitHubProject]:
        """根据ID获取GitHub项目"""
        return GitHubProject.query.get(project_id)

    # GitLab评审相关操作
    @staticmethod
    def create_gitlab_review(project_id: str, ai_name: str, review_content: str, quality_score: Optional[float],
                             commit_sha: str, pr_mr_id: str, branch: Optional[str] = None) -> GitLabReview:
        """创建GitLab评审"""
        review = GitLabReview(project_id=project_id, ai_name=ai_name, review_content=review_content,
            quality_score=quality_score, commit_sha=commit_sha, pr_mr_id=pr_mr_id, branch=branch)
        db.session.add(review)
        db.session.commit()
        return review

    @staticmethod
    def get_gitlab_reviews_by_project(project_id: str) -> List[GitLabReview]:
        """获取项目的所有GitLab评审"""
        return GitLabReview.query.filter_by(project_id=project_id).order_by(GitLabReview.created_at.desc()).all()

    @staticmethod
    def get_gitlab_reviews_by_project_and_pr(project_id: str, pr_mr_id: str) -> List[GitLabReview]:
        """获取项目特定PR/MR的所有评审"""
        return GitLabReview.query.filter_by(project_id=project_id, pr_mr_id=pr_mr_id).order_by(
            GitLabReview.created_at.desc()).all()

    # GitHub评审相关操作
    @staticmethod
    def create_github_review(project_id: str, ai_name: str, review_content: str, quality_score: Optional[float],
                             commit_sha: str, pr_mr_id: str, branch: Optional[str] = None) -> GitHubReview:
        """创建GitHub评审"""
        review = GitHubReview(project_id=project_id, ai_name=ai_name, review_content=review_content,
            quality_score=quality_score, commit_sha=commit_sha, pr_mr_id=pr_mr_id, branch=branch)
        db.session.add(review)
        db.session.commit()
        return review

    @staticmethod
    def get_github_reviews_by_project(project_id: str) -> List[GitHubReview]:
        """获取项目的所有GitHub评审"""
        return GitHubReview.query.filter_by(project_id=project_id).order_by(GitHubReview.created_at.desc()).all()

    @staticmethod
    def get_github_reviews_by_project_and_pr(project_id: str, pr_mr_id: str) -> List[GitHubReview]:
        """获取项目特定PR/MR的所有评审"""
        return GitHubReview.query.filter_by(project_id=project_id, pr_mr_id=pr_mr_id).order_by(
            GitHubReview.created_at.desc()).all()

    # 通用查询方法
    @staticmethod
    def get_user_projects(user_id: str) -> Dict[str, List[Dict[str, Any]]]:
        """获取用户的所有项目"""
        gitlab_projects = [p.to_dict() for p in DatabaseService.get_gitlab_projects_by_user(user_id)]
        github_projects = [p.to_dict() for p in DatabaseService.get_github_projects_by_user(user_id)]

        return {'gitlab': gitlab_projects, 'github': github_projects}

    @staticmethod
    def get_project_reviews(project_type: str, project_id: str) -> List[Dict[str, Any]]:
        """获取项目的所有评审"""
        if project_type == 'gitlab':
            return [r.to_dict() for r in DatabaseService.get_gitlab_reviews_by_project(project_id)]
        elif project_type == 'github':
            return [r.to_dict() for r in DatabaseService.get_github_reviews_by_project(project_id)]
        else:
            return []

    # 删除操作
    @staticmethod
    def delete_gitlab_project(project_id: str) -> bool:
        """删除GitLab项目及其相关评审"""
        project = GitLabProject.query.get(project_id)
        if project:
            db.session.delete(project)
            db.session.commit()
            return True
        return False

    @staticmethod
    def delete_github_project(project_id: str) -> bool:
        """删除GitHub项目及其相关评审"""
        project = GitHubProject.query.get(project_id)
        if project:
            db.session.delete(project)
            db.session.commit()
            return True
        return False
