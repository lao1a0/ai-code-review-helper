import json
import logging
from typing import Any, Dict, Optional

from langchain.agents import create_agent
from langchain_core.tools import tool

from config.postgres_config import github_repo_configs, gitlab_project_configs, save_config_to_postgres, delete_config_from_postgres
from services.langchain_factory import get_chat_model

logger = logging.getLogger(__name__)


def _save_to_postgres(config_type: str, key: str, value: Dict[str, Any]) -> None:
    try:
        save_config_to_postgres(config_type, key, value)
    except Exception:
        logger.exception("Failed to save config to PostgreSQL.")


def _delete_from_postgres(config_type: str, key: str) -> None:
    try:
        delete_config_from_postgres(config_type, key)
    except Exception:
        logger.exception("Failed to delete config from PostgreSQL.")


def build_agent():
    @tool
    def github_list() -> str:
        """List configured GitHub repos."""
        repos = sorted(list((github_repo_configs or {}).keys()))
        if not repos:
            return "当前没有配置任何 GitHub 仓库。"
        return "已配置的 GitHub 仓库：\n- " + "\n- ".join(repos)

    @tool
    def gitlab_list() -> str:
        """List configured GitLab projects."""
        projects = sorted(list((gitlab_project_configs or {}).keys()), key=lambda x: int(x) if str(x).isdigit() else str(x))
        if not projects:
            return "当前没有配置任何 GitLab 项目。"
        return "已配置的 GitLab 项目：\n- " + "\n- ".join(projects)

    @tool
    def github_add(repo_full_name: str, secret: str, token: str) -> str:
        """Add/update a GitHub repo config. Args: repo_full_name=owner/repo, secret, token."""
        repo_full_name = (repo_full_name or "").strip()
        if not repo_full_name or "/" not in repo_full_name:
            return "repo_full_name 无效，应为 owner/repo。"
        secret = (secret or "").strip()
        token = (token or "").strip()
        if not secret or not token:
            return "secret/token 不能为空。"
        conf = {"secret": secret, "token": token}
        github_repo_configs[repo_full_name] = conf
        _save_to_postgres('github', repo_full_name, conf)
        return f"已添加/更新 GitHub 仓库：{repo_full_name}"

    @tool
    def github_delete(repo_full_name: str) -> str:
        """Delete a GitHub repo config. Args: repo_full_name=owner/repo."""
        repo_full_name = (repo_full_name or "").strip()
        if repo_full_name not in (github_repo_configs or {}):
            return f"未找到 GitHub 仓库配置：{repo_full_name}"
        del github_repo_configs[repo_full_name]
        _delete_from_postgres('github', repo_full_name)
        return f"已删除 GitHub 仓库配置：{repo_full_name}"

    @tool
    def gitlab_add(project_id: str, secret: str, token: str, instance_url: Optional[str] = None) -> str:
        """Add/update a GitLab project config. Args: project_id, secret, token, instance_url(optional)."""
        project_id = (project_id or "").strip()
        if not project_id:
            return "project_id 不能为空。"
        secret = (secret or "").strip()
        token = (token or "").strip()
        if not secret or not token:
            return "secret/token 不能为空。"
        conf = {"secret": secret, "token": token}
        if instance_url:
            conf["instance_url"] = str(instance_url).strip()
        gitlab_project_configs[project_id] = conf
        _save_to_postgres('gitlab', project_id, conf)
        return f"已添加/更新 GitLab 项目：{project_id}"

    @tool
    def gitlab_delete(project_id: str) -> str:
        """Delete a GitLab project config. Args: project_id."""
        project_id = (project_id or "").strip()
        if project_id not in (gitlab_project_configs or {}):
            return f"未找到 GitLab 项目配置：{project_id}"
        del gitlab_project_configs[project_id]
        _delete_from_postgres('gitlab', project_id)
        return f"已删除 GitLab 项目配置：{project_id}"

    system = ("你是一个用于配置本系统 GitHub/GitLab 的运维助手。\n"
              "你只能通过提供的工具函数完成操作（列出/添加/删除）。\n"
              "当用户意图不明确时，先追问缺失字段（repo_full_name/project_id/secret/token）。\n"
              "回复用中文，简洁。")

    tools = [github_list, gitlab_list, github_add, github_delete, gitlab_add, gitlab_delete]
    llm = get_chat_model()

    # 使用langgraph的create_react_agent替代旧的create_openai_tools_agent
    agent = create_agent(llm, tools, system_prompt=system)

    return agent


_AGENT = None


def run_langchain_agent(message: str) -> str:
    global _AGENT
    if _AGENT is None:
        _AGENT = build_agent()

    try:
        # 使用langgraph的invoke方法
        out = _AGENT.invoke({"messages": [("human", (message or "").strip())]})

        # 从messages中提取最后一条AI回复
        if isinstance(out, dict) and "messages" in out:
            messages = out["messages"]
            for msg in reversed(messages):
                if hasattr(msg, 'type') and msg.type == 'ai':
                    return str(msg.content or "").strip()
                elif isinstance(msg, dict) and msg.get('type') == 'ai':
                    return str(msg.get('content', '')).strip()

        return str(out).strip()
    except Exception as e:
        logger.error(f"Agent execution error: {e}")
        return f"执行出错：{str(e)}"

if __name__ == '__main__':
    run_langchain_agent()