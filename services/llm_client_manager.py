import logging
from typing import Optional

from services.langchain_factory import refresh_chat_model

logger = logging.getLogger(__name__)


def initialize_openai_client():
    """
    Backward-compatible name.
    In LangChain mode we don't keep a long-lived OpenAI SDK client; we just refresh cached ChatModel.
    """
    refresh_chat_model()
    logger.info("LangChain ChatModel cache refreshed.")


def get_openai_client() -> Optional[object]:
    """
    Backward-compatible shim.
    Older code used OpenAI SDK client; new code should not rely on this.
    """
    return None
