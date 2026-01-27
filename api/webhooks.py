"""
Webhook routes for GitHub/GitLab integration
"""
import logging
from flask import Blueprint, request, jsonify
from core.services.webhook import get_webhook_service

logger = logging.getLogger(__name__)

webhooks_bp = Blueprint('webhooks', __name__, url_prefix='/webhooks')
webhook_service = get_webhook_service()

@webhooks_bp.route('/github', methods=['POST'])
def github_webhook():
    """GitHub webhook endpoint"""
    try:
        # Get payload
        payload = request.get_json()
        if not payload:
            logger.error("No JSON payload in GitHub webhook")
            return jsonify({'error': 'No JSON payload'}), 400
        
        # Process webhook
        success = webhook_service.process_github_webhook(payload)
        
        if success:
            return jsonify({'status': 'processed'}), 200
        else:
            return jsonify({'error': 'Processing failed'}), 500
            
    except Exception as e:
        logger.error(f"Error in GitHub webhook: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@webhooks_bp.route('/gitlab', methods=['POST'])
def gitlab_webhook():
    """GitLab webhook endpoint"""
    try:
        # Get payload
        payload = request.get_json()
        if not payload:
            logger.error("No JSON payload in GitLab webhook")
            return jsonify({'error': 'No JSON payload'}), 400
        
        # Process webhook
        success = webhook_service.process_gitlab_webhook(payload)
        
        if success:
            return jsonify({'status': 'processed'}), 200
        else:
            return jsonify({'error': 'Processing failed'}), 500
            
    except Exception as e:
        logger.error(f"Error in GitLab webhook: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@webhooks_bp.route('/test', methods=['GET'])
def test_webhook():
    """Test webhook endpoint"""
    return jsonify({
        'status': 'webhook service is running',
        'endpoints': {
            'github': '/webhooks/github',
            'gitlab': '/webhooks/gitlab'
        }
    }), 200
