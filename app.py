import logging
import os

from flask import Flask, redirect, render_template

from config.core_config import SERVER_HOST, SERVER_PORT
from config.database_config import DatabaseConfig
from db.models import db
from routes.config_routes import bp as config_bp
from routes.console_routes import bp as console_bp
from routes.webhooks_routes import bp as webhooks_bp
from config.postgres_config import init_postgres_config
from services.llm_client_manager import initialize_openai_client

logger = logging.getLogger(__name__)

# 创建Flask应用
app = Flask(__name__, template_folder="web/templates", static_folder="web/static")

# 配置数据库
app.config.update(DatabaseConfig.get_config())
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')

# 初始化扩展
db.init_app(app)

# One-time init: LLM
initialize_openai_client()

# 注册蓝图
app.register_blueprint(config_bp)
app.register_blueprint(console_bp)
app.register_blueprint(webhooks_bp)

@app.get("/")
def _index():
    return render_template("console.html")

@app.get("/review_results")
def _review_results_page():
    return redirect("/console")

@app.get("/chat")
def _chat_page():
    return redirect("/console")

@app.get("/admin")
def _admin_page():
    return redirect("/console")

# 创建数据库表
with app.app_context():
    try:
        db.create_all()
        logger.info("数据库表创建成功")
        # 初始化PostgreSQL配置存储
        init_postgres_config()
    except Exception as e:
        logger.error(f"初始化数据库失败: {e}")

if __name__ == '__main__':
    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=True)
