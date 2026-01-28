import uuid
from datetime import datetime

from db.models import db

class Config(db.Model):
    """配置模型，用于存储GitHub和GitLab的配置，替换Redis中的配置存储"""
    __tablename__ = 'configs'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    config_type = db.Column(db.String(50), nullable=False)  # 'github' or 'gitlab'
    key = db.Column(db.String(200), nullable=False)  # repo full name for github, project id for gitlab

    config_json = db.Column(db.Text, nullable=False)  # JSON string of config data

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # 复合唯一约束
    __table_args__ = (
        db.UniqueConstraint('config_type', 'key', name='unique_config'),
    )

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'config_type': self.config_type,
            'key': self.key,
            'config_json': self.config_json,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }