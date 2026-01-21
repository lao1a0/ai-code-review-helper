import logging

from flask import Flask, redirect

from config.core_config import SERVER_HOST, SERVER_PORT
from config.redis_config import init_redis_client, load_configs_from_redis
from routes.config_routes import bp as config_bp
from routes.console_routes import bp as console_bp
from routes.webhooks_routes import bp as webhooks_bp
from services.llm_client_manager import initialize_openai_client

logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder="web/templates", static_folder="web/static")

# One-time init: LLM + Redis-backed configs.
initialize_openai_client()
if init_redis_client() is not None:
    load_configs_from_redis()

app.register_blueprint(config_bp)
app.register_blueprint(console_bp)
app.register_blueprint(webhooks_bp)


@app.get("/")
def _index():
    return redirect("/console")


@app.get("/review_results")
def _review_results_page():
    return redirect("/console")


@app.get("/chat")
def _chat_page():
    return redirect("/console")


@app.get("/admin")
def _admin_page():
    return redirect("/console")


if __name__ == '__main__':
    app.run(host=SERVER_HOST, port=SERVER_PORT)
