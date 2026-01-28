"""
Project API routes
"""
import logging
from flask import Blueprint, jsonify
from flask_login import login_required
from core.models import Project

logger = logging.getLogger(__name__)

projects_bp = Blueprint('projects', __name__, url_prefix='/api')


@projects_bp.route('/projects', methods=['GET'])
@login_required
def list_projects():
    """List projects from the database."""
    try:
        projects = Project.query.order_by(Project.created_at.desc()).all()
        return jsonify({
            'success': True,
            'projects': [p.to_dict() for p in projects]
        })
    except Exception as exc:
        logger.error(f"Error loading projects: {exc}")
        return jsonify({
            'success': False,
            'error': str(exc)
        }), 500
