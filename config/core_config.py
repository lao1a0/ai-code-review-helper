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

def load_configs():
    """从 .env 文件加载应用配置"""
    candidates: list[Path] = []
    candidates.extend([Path.cwd() / ".env", Path(__file__).resolve().parent / ".env"])
    for candidate in candidates:
        if candidate and candidate.is_file():
            return dotenv_values(candidate)
    logger.warning("未找到 .env 文件（可通过 ENV_FILE 指定），将使用默认配置。")
    return {}

# --- 应用可配置项 (内存字典，从 .env 文件加载，可被 API 修改) ---
app_configs = load_configs()  # --- ---
