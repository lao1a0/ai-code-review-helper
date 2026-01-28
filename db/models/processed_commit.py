import uuid
from datetime import datetime

from db.models import db

class ProcessedCommit(db.Model):
    """已处理提交模型，用于替换Redis中的已处理提交跟踪"""
    __tablename__ = 'processed_commits'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vcs_type = db.Column(db.String(50), nullable=False)  # github, gitlab, etc.
    identifier = db.Column(db.String(200), nullable=False)  # repo full name or project id
    pr_mr_id = db.Column(db.String(50), nullable=False)
    commit_sha = db.Column(db.String(40), nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # 复合唯一约束，确保不会重复处理同一个提交
    __table_args__ = (
        db.UniqueConstraint('vcs_type', 'identifier', 'pr_mr_id', 'commit_sha', name='unique_processed_commit'),
    )

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'vcs_type': self.vcs_type,
            'identifier': self.identifier,
            'pr_mr_id': self.pr_mr_id,
            'commit_sha': self.commit_sha,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }