import json
import re


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


def parse_agent_command(message: str) -> dict:
    msg = (message or "").strip()
    if not msg:
        return {"action": "noop"}

    lowered = msg.lower()
    if lowered in {"help", "?", "h", "帮助"} or "帮助" in msg:
        return {"action": "help"}

    # JSON-first (more reliable).
    if msg.startswith("{") and msg.endswith("}"):
        try:
            payload = json.loads(msg)
            if isinstance(payload, dict) and payload.get("action"):
                return payload
        except Exception:
            pass

    if ("列出" in msg or "list" in lowered) and "github" in lowered:
        return {"action": "github_list"}
    if ("列出" in msg or "list" in lowered) and "gitlab" in lowered:
        return {"action": "gitlab_list"}

    if ("删除" in msg or "delete" in lowered) and "github" in lowered:
        repo_match = re.search(r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", msg)
        return {"action": "github_delete", "repo_full_name": repo_match.group(1) if repo_match else None}
    if ("删除" in msg or "delete" in lowered) and "gitlab" in lowered:
        pid_match = re.search(r"\b(\d+)\b", msg)
        return {"action": "gitlab_delete", "project_id": pid_match.group(1) if pid_match else None}

    if ("添加" in msg or "add" in lowered or "更新" in msg or "update" in lowered) and "github" in lowered:
        repo_match = re.search(r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", msg)
        kv = _extract_kv_pairs(msg)
        return {
            "action": "github_add",
            "repo_full_name": kv.get("repo_full_name") or kv.get("repo") or (repo_match.group(1) if repo_match else None),
            "secret": kv.get("secret"),
            "token": kv.get("token"),
        }

    if ("添加" in msg or "add" in lowered or "更新" in msg or "update" in lowered) and "gitlab" in lowered:
        kv = _extract_kv_pairs(msg)
        pid_match = re.search(r"\b(\d+)\b", msg)
        return {
            "action": "gitlab_add",
            "project_id": kv.get("project_id") or (pid_match.group(1) if pid_match else None),
            "secret": kv.get("secret"),
            "token": kv.get("token"),
            "instance_url": kv.get("instance_url") or kv.get("url"),
        }

    return {"action": "unknown", "message": msg}


def agent_help_text() -> str:
    return (
        "我可以帮你配置 GitHub / GitLab。\n\n"
        "常用指令：\n"
        "- 列出 GitHub 仓库\n"
        "- 添加 GitHub：owner/repo secret=xxx token=yyy\n"
        "- 删除 GitHub：owner/repo\n"
        "- 列出 GitLab 项目\n"
        "- 添加 GitLab：project_id=123 secret=xxx token=yyy (instance_url 可选)\n"
        "- 删除 GitLab：project_id=123\n\n"
        "也可以直接发 JSON（更稳定）：\n"
        '{"action":"github_add","repo_full_name":"owner/repo","secret":"xxx","token":"yyy"}\n'
        '{"action":"gitlab_add","project_id":"123","secret":"xxx","token":"yyy","instance_url":"https://gitlab.example.com"}'
    )
