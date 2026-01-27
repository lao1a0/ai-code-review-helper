"""
AI Code Review Helper - Refactored Application
"""
import logging
import os
from flask import Flask, redirect, render_template
from flask_login import login_required

# Import configuration
from config.settings import get_config, SERVER_CONFIG

# Import models and database
from core.models import db, login_manager

# Import API blueprints
from api import auth_bp, console_bp, webhooks_bp

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_app():
    """Application factory"""
    app = Flask(__name__, 
                template_folder="web/templates", 
                static_folder="web/static")
    
    # Load configuration
    app.config.update(get_config())
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'  # type: ignore
    login_manager.login_message = '请先登录'
    login_manager.login_message_category = 'info'
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(console_bp)
    app.register_blueprint(webhooks_bp)
    
    # Routes
    @app.get("/")
    def _index():
        return render_template("console.html")
    
    @app.get("/review_results")
    @login_required
    def _review_results_page():
        return redirect("/console")
    
    @app.get("/chat")
    @login_required
    def _chat_page():
        return redirect("/console")
    
    @app.get("/admin")
    @login_required
    def _admin_page():
        return redirect("/console")
    
    return app

def init_database(app):
    """Initialize database"""
    with app.app_context():
        try:
            db.create_all()
            logger.info("数据库表创建成功")
        except Exception as e:
            logger.error(f"初始化数据库失败: {e}")
            raise

if __name__ == '__main__':
    app = create_app()
    init_database(app)

    logger.info(f"Starting AI Code Review Helper on {SERVER_CONFIG['HOST']}:{SERVER_CONFIG['PORT']}")
    app.run(
        host=SERVER_CONFIG['HOST'],
        port=SERVER_CONFIG['PORT'],
        debug=SERVER_CONFIG['DEBUG']
    )
