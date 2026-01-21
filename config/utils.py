import hashlib
import hmac
import logging
import re
from functools import wraps

from flask import request, abort

from config.core_config import ADMIN_API_KEY

logger = logging.getLogger(__name__)


def parse_single_file_diff(diff_text, file_path, old_file_path=None):
    """
    解析单个文件的 unified diff 格式文本，提取变更信息。
    返回包含该文件变更详情和上下文的字典。
    """
    file_changes = {"path": file_path, "old_path": old_file_path, "changes": [], "context": {"old": [], "new": []},
                    "lines_changed": 0}

    old_line_num_start = 0
    new_line_num_start = 0
    old_line_num_current = 0
    new_line_num_current = 0
    hunk_context_lines = []

    lines = diff_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith('--- ') or line.startswith('+++ '):
            i += 1
            continue
        elif line.startswith('@@ '):
            match = re.match(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', line)
            if match:
                old_line_num_start = int(match.group(1))
                new_line_num_start = int(match.group(3))
                old_line_num_current = old_line_num_start
                new_line_num_current = new_line_num_start
                if hunk_context_lines:  # 将上一个 hunk 的上下文添加到 file_changes
                    file_changes["context"]["old"].extend(hunk_context_lines)
                    file_changes["context"]["new"].extend(hunk_context_lines)
                    hunk_context_lines = []  # 为新的 hunk 重置
            else:
                logger.warning(f"警告: 无法解析 {file_path} 中的 hunk 标头: {line}")
                old_line_num_start = 0  # 重置行号计数器
                new_line_num_start = 0
                old_line_num_current = 0
                new_line_num_current = 0
        elif line.startswith('+'):
            file_changes["changes"].append(
                {"type": "add", "old_line": None, "new_line": new_line_num_current, "content": line[1:]})
            new_line_num_current += 1
        elif line.startswith('-'):
            file_changes["changes"].append(
                {"type": "delete", "old_line": old_line_num_current, "new_line": None, "content": line[1:]})
            old_line_num_current += 1
        elif line.startswith(' '):  # Context line
            hunk_context_lines.append(f"{old_line_num_current} -> {new_line_num_current}: {line[1:]}")
            old_line_num_current += 1
            new_line_num_current += 1
        i += 1

    if hunk_context_lines:  # 添加最后一个 hunk 的上下文
        file_changes["context"]["old"].extend(hunk_context_lines)
        file_changes["context"]["new"].extend(hunk_context_lines)

    limit = 20  # 限制上下文行数
    file_changes["context"]["old"] = "\n".join(file_changes["context"]["old"][-limit:])
    file_changes["context"]["new"] = "\n".join(file_changes["context"]["new"][-limit:])
    file_changes["lines_changed"] = len([c for c in file_changes["changes"] if c['type'] in ['add', 'delete']])

    return file_changes


def require_admin_key(f):
    """装饰器：验证请求中是否包含正确的 Admin API Key。

    Supports:
    - Header: X-Admin-API-Key
    - Cookie: ADMIN_API_KEY (useful for direct browser access after visiting /console)
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-Admin-API-Key') or request.cookies.get('ADMIN_API_KEY')
        if not api_key:
            logger.warning("检测到对配置端点的未授权访问尝试（缺少 Admin Key）。ip=%s path=%s",
                           request.remote_addr, request.path)
            abort(401, "未授权: 缺少 Admin Key（X-Admin-API-Key 请求头或 ADMIN_API_KEY Cookie）。")

        if not hmac.compare_digest(api_key, ADMIN_API_KEY):
            logger.warning("检测到对配置端点的未授权访问尝试（Admin Key 无效）。ip=%s path=%s",
                           request.remote_addr, request.path)
            abort(401, "未授权: Admin Key 无效。")
        return f(*args, **kwargs)

    return decorated_function


def verify_github_signature(req, secret):
    """验证 GitHub Webhook 签名 (HMAC-SHA256)"""
    signature_header = req.headers.get('X-Hub-Signature-256')
    if not signature_header:
        logger.error("错误: X-Hub-Signature-256 请求头缺失。")
        return False

    sha_name, signature = signature_header.split('=', 1)
    if sha_name != 'sha256':
        logger.error(f"错误: 签名使用不支持的算法 {sha_name}。")
        return False

    if not secret:
        logger.error("错误: 此仓库未配置 Webhook secret。")
        return False

    mac = hmac.new(secret.encode('utf-8'), msg=req.data, digestmod=hashlib.sha256)
    if not hmac.compare_digest(mac.hexdigest(), signature):
        logger.error("错误: 无效的 X-Hub-Signature-256。")
        return False

    return True


def verify_gitlab_signature(req, secret):
    """验证 GitLab Webhook 签名 (使用项目特定的 Secret)"""
    gitlab_token = req.headers.get('X-Gitlab-Token')
    if not gitlab_token:
        logger.error("错误: X-Gitlab-Token 请求头缺失。")
        return False
    if not secret:
        logger.error("错误: 此项目未配置 Webhook secret。")
        return False

    if not hmac.compare_digest(gitlab_token, secret):
        logger.error(f"错误: 无效的 X-Gitlab-Token。")
        return False
    return True

def _extract_kv_pairs(text: str) -> dict:
    """
    Extract key/value pairs from free-form text.
    Supports:
      - key=value
      - key: value
      - key：value
    Values may be quoted.
    """
    pairs = {}
    key_re = r"(repo_full_name|repo|owner_repo|project_id|secret|token|instance_url|url)"
    val_re = r"(\"[^\"]*\"|'[^']*'|[^\\s,]+)"
    for m in re.finditer(key_re + r"\s*[:=：]\s*" + val_re, text, flags=re.IGNORECASE):
        k = (m.group(1) or "").lower()
        v = (m.group(2) or "").strip()
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            v = v[1:-1]
        pairs[k] = v
    return pairs


def _parse_agent_command(message: str) -> dict:
    msg = (message or "").strip()
    if not msg:
        return {"action": "noop"}

    lowered = msg.lower()

    if lowered in {"help", "?", "h", "\u5e2e\u52a9"} or "\u5e2e\u52a9" in msg:
        return {"action": "help"}

    # JSON-first (more reliable).
    if msg.startswith("{") and msg.endswith("}"):
        try:
            payload = json.loads(msg)
            if isinstance(payload, dict) and payload.get("action"):
                return payload
        except Exception:
            pass

    if ("\u5217\u51fa" in msg or "list" in lowered) and "github" in lowered:
        return {"action": "github_list"}
    if ("\u5217\u51fa" in msg or "list" in lowered) and "gitlab" in lowered:
        return {"action": "gitlab_list"}

    if ("\u5220\u9664" in msg or "delete" in lowered) and "github" in lowered:
        repo_match = re.search(r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", msg)
        return {"action": "github_delete", "repo_full_name": repo_match.group(1) if repo_match else None}
    if ("\u5220\u9664" in msg or "delete" in lowered) and "gitlab" in lowered:
        pid_match = re.search(r"\b(\d+)\b", msg)
        return {"action": "gitlab_delete", "project_id": pid_match.group(1) if pid_match else None}

    if ("\u6dfb\u52a0" in msg or "add" in lowered or "\u66f4\u65b0" in msg or "update" in lowered) and "github" in lowered:
        repo_match = re.search(r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", msg)
        kv = _extract_kv_pairs(msg)
        return {"action": "github_add", "repo_full_name": kv.get("repo_full_name") or kv.get("repo") or (repo_match.group(1) if repo_match else None), "secret": kv.get("secret"), "token": kv.get("token"), }

    if ("\u6dfb\u52a0" in msg or "add" in lowered or "\u66f4\u65b0" in msg or "update" in lowered) and "gitlab" in lowered:
        kv = _extract_kv_pairs(msg)
        pid_match = re.search(r"\b(\d+)\b", msg)
        return {"action": "gitlab_add", "project_id": kv.get("project_id") or (pid_match.group(1) if pid_match else None), "secret": kv.get("secret"), "token": kv.get("token"), "instance_url": kv.get("instance_url") or kv.get("url"), }

    return {"action": "unknown", "message": msg}


def _agent_help_text() -> str:
    return ("我可以帮你配置 GitHub / GitLab。\\n\\n"
            "常用指令：\\n"
            "- 列出 GitHub 仓库\\n"
            "- 添加 GitHub：owner/repo secret=xxx token=yyy\\n"
            "- 删除 GitHub：owner/repo\\n"
            "- 列出 GitLab 项目\\n"
            "- 添加 GitLab：project_id=123 secret=xxx token=yyy (instance_url 可选)\\n"
            "- 删除 GitLab：project_id=123\\n\\n"
            "也可以直接发 JSON（更稳定）：\\n"
            "{\\\"action\\\":\\\"github_add\\\",\\\"repo_full_name\\\":\\\"owner/repo\\\",\\\"secret\\\":\\\"xxx\\\",\\\"token\\\":\\\"yyy\\\"}\\n"
            "{\\\"action\\\":\\\"gitlab_add\\\",\\\"project_id\\\":\\\"123\\\",\\\"secret\\\":\\\"xxx\\\",\\\"token\\\":\\\"yyy\\\",\\\"instance_url\\\":\\\"https://gitlab.example.com\\\"}")
