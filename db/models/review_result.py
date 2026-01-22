import uuid
from datetime import datetime

from db.models import db

class ReviewResult(db.Model):
    """审查结果模型，用于替换Redis中的审查结果存储"""
    __tablename__ = 'review_results'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vcs_type = db.Column(db.String(50), nullable=False)  # github, gitlab, etc.
    identifier = db.Column(db.String(200), nullable=False)  # repo full name or project id
    pr_mr_id = db.Column(db.String(50), nullable=False)
    commit_sha = db.Column(db.String(40), nullable=False)

    review_json = db.Column(db.Text, nullable=False)  # JSON string of review results

    # 元数据
    project_name = db.Column(db.String(200), nullable=True)
    branch = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # 复合唯一约束，确保每个commit只有一个审查结果
    __table_args__ = (
        db.UniqueConstraint('vcs_type', 'identifier', 'pr_mr_id', 'commit_sha', name='unique_review_result'),
    )

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'vcs_type': self.vcs_type,
            'identifier': self.identifier,
            'pr_mr_id': self.pr_mr_id,
            'commit_sha': self.commit_sha,
            'review_json': self.review_json,
            'project_name': self.project_name,
            'branch': self.branch,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }