import logging
import datetime
from typing import Optional

from flask import Flask

from config.postgres_config import save_review_results

logger = logging.getLogger(__name__)


def _save_review_results_and_log(vcs_type: str, identifier: str, pr_mr_id: str, commit_sha: str, review_json_string: str, project_name_for_gitlab: Optional[str] = None, branch: Optional[str] = None, project_url: Optional[str] = None):
    """统一保存审查结果到数据库（并补齐 created_at 元信息）。"""
    if not commit_sha:
        logger.warning(f"警告: {vcs_type.capitalize()} {identifier}#{pr_mr_id} 的 commit_sha 为空。无法保存审查结果。")
        return

    # Save timestamp for list ordering in the console.
    created_at = datetime.datetime.now().isoformat()

    try:
        # 统一处理所有 github* 和 gitlab* 类型
        if vcs_type.startswith('github'): # 包括 'github' 和 'github_general'
            save_review_results(vcs_type, identifier, pr_mr_id, commit_sha, review_json_string, branch=branch, created_at=created_at, project_url=project_url)
        elif vcs_type.startswith('gitlab'): # 包括 'gitlab' 和 'gitlab_general'
            save_review_results(vcs_type, identifier, pr_mr_id, commit_sha, review_json_string, project_name=project_name_for_gitlab, branch=branch, created_at=created_at, project_url=project_url)
        else:
            logger.error(f"未知的 VCS 类型 '{vcs_type}'，无法保存审查结果。")
            return

        # save_review_results already logs details; keep a single line for tracing.
        logger.info(f"{vcs_type.capitalize()}: 审查结果保存调用完成，针对 commit {commit_sha}。")

    except Exception as e:
        # save_review_results 内部已经有错误日志，这里可以捕获更通用的错误或决定是否需要额外日志
        logger.error(f"调用 save_review_results 时发生意外错误 ({vcs_type} {identifier}#{pr_mr_id}, Commit: {commit_sha}): {e}")

def run_with_app_context(app: Optional[Flask], func, *args, **kwargs):
    """Run a callable inside a Flask app context for background threads."""
    if app is None:
        return func(*args, **kwargs)
    with app.app_context():
        return func(*args, **kwargs)

def handle_async_task_exception(future, logger_app_factory=None):
    """
    处理 ThreadPoolExecutor 提交的异步任务中未捕获的异常。
    此函数作为 Future 对象的完成回调。
    """
    try:
        exception = future.exception()
        if exception:
            # 使用 logger 记录异常和堆栈跟踪
            if logger_app_factory:
                logger_app_factory.error(
                    f"后台异步任务执行失败。",
                    exc_info=exception  # 这会自动包含堆栈跟踪
                )
            else:
                logger.error(
                    f"后台异步任务执行失败。",
                    exc_info=exception
                )
            # 这里可以根据需要添加其他错误处理逻辑，例如发送通知
    except Exception as e:
        # 捕获回调函数本身可能发生的任何错误
        logger.error(
            f"处理异步任务异常的回调函数自身发生错误: {e}",
            exc_info=True
        )
