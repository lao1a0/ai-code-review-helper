import logging
import os
from pathlib import Path
from typing import Optional

from dotenv import dotenv_values, load_dotenv

logger = logging.getLogger(__name__)


def _load_env_file():
    env_file_override = os.environ.get("ENV_FILE")
    candidates = []
    if env_file_override:
        candidates.append(Path(env_file_override))
    candidates.extend([Path.cwd() / ".env", Path(__file__).resolve().parent / ".env"])

    for candidate in candidates:
        try:
            if candidate and candidate.is_file():
                load_dotenv(dotenv_path=str(candidate), override=False)
                return str(candidate)
        except OSError:
            continue
    load_dotenv(override=False)
    return None


def _resolve_env_file_path() -> Optional[str]:
    """
    Resolve .env location for reading config values.

    Priority:
    1) ENV_FILE (explicit path)
    2) CWD/.env
    3) api/.env (next to this file)
    """
    env_file_override = os.environ.get("ENV_FILE")
    candidates: list[Path] = []
    if env_file_override:
        candidates.append(Path(env_file_override))
    candidates.extend([Path.cwd() / ".env", Path(__file__).resolve().parent / ".env"])

    for candidate in candidates:
        try:
            if candidate and candidate.is_file():
                return str(candidate)
        except OSError:
            continue
    return None


def load_app_configs_from_env():
    """从 .env 文件加载应用配置"""
    env_path = _resolve_env_file_path()
    if not env_path:
        logger.warning("未找到 .env 文件（可通过 ENV_FILE 指定），将使用默认配置。")
        env_values = {}
    else:
        env_values = dotenv_values(env_path)
    return {"OPENAI_API_BASE_URL": env_values.get("OPENAI_API_BASE_URL", "https://api.openai.com/v1"),
            "OPENAI_API_KEY": env_values.get("OPENAI_API_KEY", "xxxx-xxxx-xxxx-xxxx"),
            "OPENAI_MODEL": env_values.get("OPENAI_MODEL", "gpt-4o"),
            # Embeddings (optional; some OpenAI-compatible providers may not support this endpoint).
            "OPENAI_EMBEDDING_MODEL": env_values.get("OPENAI_EMBEDDING_MODEL", "text-embedding-3-small"),
            "GITHUB_API_URL": env_values.get("GITHUB_API_URL", "https://api.github.com"),
            "GITHUB_ACCESS_TOKEN": env_values.get("GITHUB_ACCESS_TOKEN", ""),
            "GITLAB_API_URL": env_values.get("GITLAB_API_URL", "https://gitlab.com/api/v4"),
            "GITLAB_INSTANCE_URL": env_values.get("GITLAB_INSTANCE_URL", "https://gitlab.com"),
            "WECOM_BOT_WEBHOOK_URL": env_values.get("WECOM_BOT_WEBHOOK_URL", ""),
            "CUSTOM_WEBHOOK_URL": env_values.get("CUSTOM_WEBHOOK_URL", ""),  # 新增：自定义通知 Webhook URL

            # Push 审计（Git push hook）配置
            "PUSH_AUDIT_ENABLED": (env_values.get("PUSH_AUDIT_ENABLED", "true") or "true").lower() == "true",
            "PUSH_AUDIT_MAX_FILES": int(env_values.get("PUSH_AUDIT_MAX_FILES", "20") or "20"),
            "PUSH_AUDIT_POST_COMMIT_COMMENT": (env_values.get("PUSH_AUDIT_POST_COMMIT_COMMENT",
                                                              "true") or "true").lower() == "true",

            # --- LLM + RAG + Skill policies (used by the console; stored in app_configs so /config/global_settings can manage them) ---
            "LLM_TEMPERATURE": float(env_values.get("LLM_TEMPERATURE", "0.2") or "0.2"),
            "LLM_MAX_CONTEXT_TOKENS": int(env_values.get("LLM_MAX_CONTEXT_TOKENS", "8000") or "8000"),
            "TOOL_CALL_POLICY": env_values.get("TOOL_CALL_POLICY", "auto") or "auto",
            "RAG_TRIGGER_POLICY": env_values.get("RAG_TRIGGER_POLICY", "on_demand") or "on_demand",
            "SKILL_READ_POLICY": env_values.get("SKILL_READ_POLICY", "on_demand") or "on_demand",

            # --- RAG retrieval knobs (hybrid retrieval) ---
            "RAG_TOP_K": int(env_values.get("RAG_TOP_K", "5") or "5"),
            "RAG_SIMILARITY_THRESHOLD": float(env_values.get("RAG_SIMILARITY_THRESHOLD", "0.2") or "0.2"),
            "RAG_HYBRID_WEIGHT": float(env_values.get("RAG_HYBRID_WEIGHT", "0.7") or "0.7"),

            # --- Notification template (placeholder) ---
            "NOTIFY_TEMPLATE": env_values.get("NOTIFY_TEMPLATE", ""), }


# Load .env into os.environ before reading module-level settings like ADMIN_API_KEY.
# This module is imported very early (e.g., via services.*), so relying on app.py to
# call _load_env_file() is too late and leads to confusing "wrong key" 401s.
_load_env_file()

# --- 全局配置 ---
# 服务器配置
SERVER_HOST = os.environ.get("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.environ.get("SERVER_PORT", "8088"))  # 应用端口 (统一端口)

# 配置管理 API Key (用于保护配置接口)
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "change_this_unified_secret_key")  # 强烈建议修改此默认值

# 应用前缀 (用于各种存储key)
APP_KEY_PREFIX = "aihelper"

# --- 应用可配置项 (内存字典，从 .env 文件加载，可被 API 修改) ---
app_configs = load_app_configs_from_env()  # --- ---
