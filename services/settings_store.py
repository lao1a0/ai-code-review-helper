import json
from typing import Any, Dict

# Settings store - now using memory only (previously used Redis)

# 全局内存存储
_MEM_AGENT_SETTINGS = {}
_MEM_PROJECT_SETTINGS = {}


def _deep_merge(base: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base or {})
    for k, v in (patch or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def get_agent_settings() -> Dict[str, Any]:
    return dict(_MEM_AGENT_SETTINGS)


def set_agent_settings(patch: Dict[str, Any]) -> Dict[str, Any]:
    global _MEM_AGENT_SETTINGS
    merged = _deep_merge(get_agent_settings(), patch or {})
    _MEM_AGENT_SETTINGS = merged
    return merged


def get_project_settings(project_key: str) -> Dict[str, Any]:
    if not project_key:
        return {}
    return dict(_MEM_PROJECT_SETTINGS.get(project_key) or {})


def set_project_settings(project_key: str, patch: Dict[str, Any]) -> Dict[str, Any]:
    if not project_key:
        return {}
    merged = _deep_merge(get_project_settings(project_key), patch or {})
    _MEM_PROJECT_SETTINGS[project_key] = merged
    return merged