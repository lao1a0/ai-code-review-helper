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
from core.services.auth import get_auth_service

# Import API blueprints
from api import auth_bp, console_bp, projects_bp, reviews_bp, webhooks_bp

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
    app.register_blueprint(projects_bp)
    app.register_blueprint(reviews_bp)
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
            env_path = os.path.join(os.path.dirname(__file__), '.env')
            _load_env_file(env_path)
            db.create_all()
            _ensure_default_user()
            logger.info("数据库初始化成功")
        except Exception as e:
            logger.error(f"数据库初始化失败：{e}")
            raise



def _load_env_file(path):
    if not os.path.isfile(path):
        return
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except Exception as exc:
        logger.warning(f"Failed to load .env: {exc}")


def _ensure_default_user():
    username = os.environ.get('ADMIN_USERNAME', 'admin')
    email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
    password = os.environ.get('ADMIN_PASSWORD', 'admin123')

    auth_service = get_auth_service()
    user = auth_service.create_user(username=username, email=email, password=password)
    if user:
        logger.info('Default admin user created (update ADMIN_USERNAME/ADMIN_EMAIL/ADMIN_PASSWORD in .env).')


if __name__ == '__main__':
    app = create_app()
    init_database(app)

    logger.info(f"Starting AI Code Review Helper on {SERVER_CONFIG['HOST']}:{SERVER_CONFIG['PORT']}")
    app.run(
        host=SERVER_CONFIG['HOST'],
        port=SERVER_CONFIG['PORT'],
        debug=SERVER_CONFIG['DEBUG']
    )
