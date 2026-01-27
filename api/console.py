"""
Console routes for the main application
"""
import logging
from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required, current_user
from core.services.review import get_review_service
from core.services.auth import get_auth_service

logger = logging.getLogger(__name__)

console_bp = Blueprint('console', __name__, url_prefix='/console')
review_service = get_review_service()
auth_service = get_auth_service()

@console_bp.route('/')
@login_required
def index():
    """Main console page"""
    try:
        # Get recent reviews for the user
        recent_reviews = review_service.get_reviews_by_platform('github', limit=10) + \
                        review_service.get_reviews_by_platform('gitlab', limit=10)
        
        # Sort by created_at and limit to 10
        recent_reviews.sort(key=lambda x: x.created_at, reverse=True)
        recent_reviews = recent_reviews[:10]
        
        return render_template('console.html', 
                             user=current_user,
                             recent_reviews=recent_reviews)
    except Exception as e:
        logger.error(f"Error loading console: {e}")
        return render_template('console.html', 
                             user=current_user,
                             recent_reviews=[],
                             error="加载数据时出错")

@console_bp.route('/reviews')
@login_required
def reviews():
    """Reviews page"""
    try:
        platform = request.args.get('platform', 'all')
        limit = int(request.args.get('limit', 50))
        
        if platform == 'all':
            github_reviews = review_service.get_reviews_by_platform('github', limit=limit//2)
            gitlab_reviews = review_service.get_reviews_by_platform('gitlab', limit=limit//2)
            reviews_list = github_reviews + gitlab_reviews
        else:
            reviews_list = review_service.get_reviews_by_platform(platform, limit=limit)
        
        # Sort by created_at
        reviews_list.sort(key=lambda x: x.created_at, reverse=True)
        
        return jsonify({
            'success': True,
            'reviews': [review.to_dict() for review in reviews_list]
        })
    except Exception as e:
        logger.error(f"Error loading reviews: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@console_bp.route('/review/<review_id>')
@login_required
def review_detail(review_id):
    """Review detail page"""
    try:
        review = review_service.get_review_by_id(review_id)
        if not review:
            return jsonify({
                'success': False,
                'error': 'Review not found'
            }), 404
        
        return jsonify({
            'success': True,
            'review': review.to_dict()
        })
    except Exception as e:
        logger.error(f"Error loading review detail: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
