import logging
import re
from functools import lru_cache
from typing import Any, Dict, Optional

from config.core_config import app_configs

logger = logging.getLogger(__name__)

_THINK_RE = re.compile(r"<think>.*?</?think>", flags=re.DOTALL | re.IGNORECASE)
_CODE_FENCE_RE = re.compile(r"```(?:\\w+\\s*)?([\\s\\S]*?)\\s*```", flags=re.DOTALL)


def _require_langchain() -> None:
    try:
        import langchain  # noqa: F401
        import langchain_openai  # noqa: F401
    except Exception as e:
        raise RuntimeError("LangChain 依赖未安装。请先执行: pip install -r requirements.txt") from e


def clean_llm_text(raw: str) -> str:
    """
    Keep behavior close to the previous OpenAI client manager:
    - strip <think> tags
    - unwrap ```...``` fences if present
    """
    text = (raw or "").strip()
    if not text:
        return ""
    text = _THINK_RE.sub("", text).strip()
    m = _CODE_FENCE_RE.search(text)
    if m:
        return (m.group(1) or "").strip()
    return text


@lru_cache(maxsize=1)
def get_chat_model():
    """
    Returns a cached ChatOpenAI (OpenAI-compatible) instance based on app_configs.

    NOTE: call refresh_chat_model() after config updates.
    """
    _require_langchain()
    from langchain_openai import ChatOpenAI

    base_url = (app_configs.get("OPENAI_API_BASE_URL") or "").strip()
    api_key = (app_configs.get("OPENAI_API_KEY") or "").strip()
    model = (app_configs.get("OPENAI_MODEL") or "gpt-4o").strip()
    temperature = float(app_configs.get("LLM_TEMPERATURE", 0.2) or 0.2)

    if not api_key or api_key == "xxxx-xxxx-xxxx-xxxx":
        raise RuntimeError("OPENAI_API_KEY 未配置（或仍为占位符），无法创建 LangChain ChatModel。")

    kwargs: Dict[str, Any] = {"model": model, "api_key": api_key, "temperature": temperature}
    if base_url:
        kwargs["base_url"] = base_url
    return ChatOpenAI(**kwargs)


def refresh_chat_model() -> None:
    """Call this after /config/global_settings updates model/base_url/key/temperature."""
    get_chat_model.cache_clear()


def invoke_chat(*, system_prompt: str, user_prompt: str, response_format_type: Optional[str] = None, ) -> str:
    """
    Minimal wrapper for chat completion.
    response_format_type mirrors the previous code ("json_object" or None).
    """
    _require_langchain()
    from langchain_core.messages import HumanMessage, SystemMessage

    llm = get_chat_model()
    if response_format_type:
        # OpenAI-compatible models may support response_format={"type":"json_object"}.
        llm = llm.bind(response_format={"type": response_format_type})

    resp = llm.invoke([SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)])
    content = getattr(resp, "content", "")
    return clean_llm_text(str(content))
