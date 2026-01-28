import hashlib
import hmac
import logging
from functools import wraps

from flask import abort, request

from config.core_config import ADMIN_API_KEY

logger = logging.getLogger(__name__)


def require_admin_key(f):
    """
    Validate Admin API key from:
    - Header: X-Admin-API-Key
    - Cookie: ADMIN_API_KEY
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get("X-Admin-API-Key") or request.cookies.get("ADMIN_API_KEY")
        if not api_key:
            logger.warning("Missing Admin Key. ip=%s path=%s", request.remote_addr, request.path)
            abort(401, "未授权: 缺少 Admin Key（X-Admin-API-Key 请求头或 ADMIN_API_KEY Cookie）。")

        if not hmac.compare_digest(api_key, ADMIN_API_KEY):
            logger.warning("Invalid Admin Key. ip=%s path=%s", request.remote_addr, request.path)
            abort(401, "未授权: Admin Key 无效。")
        return f(*args, **kwargs)

    return decorated_function


def verify_github_signature(req, secret: str) -> bool:
    signature_header = req.headers.get("X-Hub-Signature-256")
    if not signature_header:
        logger.error("Missing X-Hub-Signature-256 header.")
        return False

    sha_name, signature = signature_header.split("=", 1)
    if sha_name != "sha256":
        logger.error("Unsupported signature algo: %s", sha_name)
        return False

    if not secret:
        logger.error("Missing repo webhook secret.")
        return False

    mac = hmac.new(secret.encode("utf-8"), msg=req.data, digestmod=hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), signature)


def verify_gitlab_signature(req, secret: str) -> bool:
    gitlab_token = req.headers.get("X-Gitlab-Token")
    if not gitlab_token:
        logger.error("Missing X-Gitlab-Token header.")
        return False
    if not secret:
        logger.error("Missing project webhook secret.")
        return False
    return hmac.compare_digest(gitlab_token, secret)

