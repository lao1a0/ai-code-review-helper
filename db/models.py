import uuid
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import UUID

db = SQLAlchemy()


class ReviewResult(db.Model):
    __tablename__ = "reviews"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_type = db.Column("projecttype", db.String(100), nullable=False)
    project = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    review_content = db.Column(db.Text, nullable=False)
    quality_score = db.Column(db.Float)
    commit_sha = db.Column(db.String(40), nullable=False)
    pr_mr_id = db.Column(db.String(50), nullable=False)
    branch = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
