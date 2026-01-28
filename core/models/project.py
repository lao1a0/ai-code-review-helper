"""
Project model for code review projects
"""
import uuid
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID
from . import db

class Project(db.Model):
    """Project model for code review projects"""
    
    __tablename__ = 'projects'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(200), nullable=False)
    platform = db.Column(db.String(50), nullable=False)  # 'github' or 'gitlab'
    repo_url = db.Column(db.String(500), nullable=False)
    project_key = db.Column(db.String(100), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    reviews = db.relationship('Review', backref='project', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Project {self.name} ({self.platform})>'
    
    def to_dict(self):
        """Convert project to dictionary"""
        return {
            'id': str(self.id),
            'name': self.name,
            'platform': self.platform,
            'repo_url': self.repo_url,
            'project_key': self.project_key,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
