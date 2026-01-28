"""
Review API routes
"""
import logging
from flask import Blueprint, jsonify, request
from core.models import Review, Project

logger = logging.getLogger(__name__)

reviews_bp = Blueprint('reviews', __name__, url_prefix='/api')


@reviews_bp.route('/reviews/list', methods=['GET'])
def list_reviews():
    """List reviews for the dashboard."""
    try:
        include_stats = request.args.get('include_stats', '0') == '1'
        reviews = Review.query.order_by(Review.created_at.desc()).limit(200).all()
        project_ids = {r.project_id for r in reviews}
        projects = {p.id: p for p in Project.query.filter(Project.id.in_(project_ids)).all()}

        items = []
        for r in reviews:
            proj = projects.get(r.project_id)
            identifier = ''
            if proj and proj.project_key:
                parts = proj.project_key.split(':', 1)
                identifier = parts[1] if len(parts) == 2 else proj.project_key
            items.append({
                'vcs_type': r.platform,
                'identifier': identifier,
                'display_name': proj.name if proj else '',
                'pr_mr_id': r.pr_mr_id,
                'risk_level': 'UNKNOWN',
                'files': [],
                'skill_hits': [],
                'rag_sources': ['code_context'],
                'created_at': r.created_at.isoformat() if r.created_at else None,
                'status': r.status
            })

        payload = {'reviews': items}
        if include_stats:
            payload['stats'] = {
                'total': len(items),
                'completed': sum(1 for r in reviews if r.status == 'completed'),
                'pending': sum(1 for r in reviews if r.status == 'pending'),
                'failed': sum(1 for r in reviews if r.status == 'failed'),
            }
        return jsonify(payload)
    except Exception as exc:
        logger.error(f"Error listing reviews: {exc}")
        return jsonify({'error': str(exc)}), 500


@reviews_bp.route('/reviews/<vcs_type>/<identifier>/<pr_mr_id>', methods=['GET'])
def review_detail(vcs_type: str, identifier: str, pr_mr_id: str):
    """Return review detail for the modal."""
    try:
        project = Project.query.filter_by(project_key=f"{vcs_type}:{identifier}").first()
        if not project:
            return jsonify({'error': 'Project not found'}), 404

        review = Review.query.filter_by(project_id=project.id, pr_mr_id=pr_mr_id).order_by(Review.created_at.desc()).first()
        if not review:
            return jsonify({'error': 'Review not found'}), 404

        return jsonify({
            'reviews_by_commit': {'latest': review.review_content or ''},
            'skill_hits': [],
            'rag_sources': ['code_context']
        })
    except Exception as exc:
        logger.error(f"Error getting review detail: {exc}")
        return jsonify({'error': str(exc)}), 500
