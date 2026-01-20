import json
from typing import Any, Dict, Optional

import config.core_config as core_config


_MEM_AGENT_SETTINGS: Dict[str, Any] = {}
_MEM_PROJECT_SETTINGS: Dict[str, Dict[str, Any]] = {}

REDIS_AGENT_SETTINGS_KEY = f"{core_config.REDIS_KEY_PREFIX}agent_settings"
REDIS_PROJECT_SETTINGS_KEY = f"{core_config.REDIS_KEY_PREFIX}project_settings"


def _deep_merge(base: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base or {})
    for k, v in (patch or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def get_agent_settings() -> Dict[str, Any]:
    if core_config.redis_client:
        try:
            raw = core_config.redis_client.get(REDIS_AGENT_SETTINGS_KEY)
            if raw:
                return json.loads(raw.decode("utf-8"))
        except Exception:
            pass
    return dict(_MEM_AGENT_SETTINGS)


def set_agent_settings(patch: Dict[str, Any]) -> Dict[str, Any]:
    global _MEM_AGENT_SETTINGS
    merged = _deep_merge(get_agent_settings(), patch or {})
    if core_config.redis_client:
        try:
            core_config.redis_client.set(REDIS_AGENT_SETTINGS_KEY, json.dumps(merged, ensure_ascii=False))
        except Exception:
            pass
    _MEM_AGENT_SETTINGS = merged
    return merged


def get_project_settings(project_key: str) -> Dict[str, Any]:
    if not project_key:
        return {}
    if core_config.redis_client:
        try:
            raw = core_config.redis_client.hget(REDIS_PROJECT_SETTINGS_KEY, project_key)
            if raw:
                return json.loads(raw.decode("utf-8"))
        except Exception:
            pass
    return dict(_MEM_PROJECT_SETTINGS.get(project_key) or {})


def set_project_settings(project_key: str, patch: Dict[str, Any]) -> Dict[str, Any]:
    if not project_key:
        return {}
    merged = _deep_merge(get_project_settings(project_key), patch or {})
    if core_config.redis_client:
        try:
            core_config.redis_client.hset(REDIS_PROJECT_SETTINGS_KEY, project_key, json.dumps(merged, ensure_ascii=False))
        except Exception:
            pass
    _MEM_PROJECT_SETTINGS[project_key] = merged
    return merged

