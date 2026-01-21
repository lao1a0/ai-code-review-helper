import json
import logging

from config.core_config import app_configs
from config.redis_config import mark_commit_as_processed
from webhooks.push_process import get_final_summary_comment_text
from webhooks.helpers import _save_review_results_and_log
from services.llm_review_general_service import get_openai_code_review_general
from services import rag_service
from services.notification_service import send_notifications
from services.vcs_service import (
    add_github_pr_general_comment,
    add_gitlab_mr_general_comment,
    get_github_pr_data_for_general_review,
    get_gitlab_mr_data_for_general_review,
)

logger = logging.getLogger(__name__)


def _process_github_general_payload(access_token, owner, repo_name, pull_number, pr_data, head_sha, repo_full_name,
                                    pr_title, pr_html_url, repo_web_url, pr_source_branch, pr_target_branch):
    """实际处理 GitHub 通用审查的核心逻辑。"""
    logger.info("GitHub (通用审查): 正在获取 PR 数据 (diffs 和文件内容)...")
    file_data_list = get_github_pr_data_for_general_review(owner, repo_name, pull_number, access_token, pr_data)

    if file_data_list is None:
        logger.warning("GitHub (通用审查): 获取 PR 数据失败。中止审查。")
        # 在异步任务中，通常会记录错误，可能不会直接返回 HTTP 响应
        return
    if not file_data_list:
        logger.info("GitHub (通用审查): 未检测到文件变更或数据。无需审查。")
        _save_review_results_and_log(  # 保存空列表表示已处理且无内容
            vcs_type='github_general', identifier=repo_full_name, pr_mr_id=str(pull_number), commit_sha=head_sha,
            review_json_string=json.dumps([]), branch=pr_source_branch)
        return

    aggregated_general_reviews_for_storage = []
    files_with_issues_details = []  # {file_path: str, issues_text: str}

    logger.info(
        f'GitHub (通用审查): 将对 {len(file_data_list)} 个文件逐一发送给 {app_configs.get("OPENAI_MODEL", "gpt-4o")} 进行审查...')

    for file_item in file_data_list:
        current_file_path = file_item.get("file_path", "Unknown File")
        logger.info(f"GitHub (通用审查): 正在对文件 {current_file_path} 进行 LLM 审查...")

        rag_payload = rag_service.build_rag_context_for_file(
            "github_general",
            repo_full_name,
            current_file_path,
            {"context": {"old": file_item.get("old_content"), "new": file_item.get("diff_text")}, "changes": []},
            top_k=int(app_configs.get("RAG_TOP_K", 5) or 5),
        )
        if rag_payload.get("enabled") and rag_payload.get("context"):
            file_item = dict(file_item)
            file_item["rag"] = {
                "sources": rag_payload.get("sources") or [],
                "context": rag_payload.get("context") or "",
            }

        review_text_for_file = get_openai_code_review_general(file_item)  # Pass single file_item

        logger.info(f"GitHub (通用审查): 文件 {current_file_path} 的 LLM 原始输出:\n{review_text_for_file}")

        if review_text_for_file and review_text_for_file.strip() and "未发现严重问题" not in review_text_for_file and "没有修改建议" not in review_text_for_file and "OpenAI client is not available" not in review_text_for_file and "Error serializing input data" not in review_text_for_file:

            logger.info(f"GitHub (通用审查): 文件 {current_file_path} 发现问题。正在添加评论...")
            comment_text_for_pr = f"**AI 审查意见 (文件: `{current_file_path}`)**\n\n{review_text_for_file}"
            add_github_pr_general_comment(owner, repo_name, pull_number, access_token, comment_text_for_pr)

            files_with_issues_details.append({"file": current_file_path, "issues": review_text_for_file})

            review_wrapper_for_file = {"file": current_file_path, "lines": {"old": None, "new": None},
                                       "category": "general Review", "severity": "INFO",
                                       "analysis": review_text_for_file, "suggestion": "请参考上述分析。"}
            used_sources = rag_payload.get("sources") or []
            if used_sources:
                review_wrapper_for_file["rag_sources"] = used_sources
            aggregated_general_reviews_for_storage.append(review_wrapper_for_file)
        else:
            logger.info(f"GitHub (通用审查): 文件 {current_file_path} 未发现问题、审查意见为空或指示无问题。")

    # After processing all files
    if aggregated_general_reviews_for_storage:
        review_json_string_for_storage = json.dumps(aggregated_general_reviews_for_storage)
        _save_review_results_and_log(vcs_type='github_general', identifier=repo_full_name, pr_mr_id=str(pull_number),
                                     commit_sha=head_sha, review_json_string=review_json_string_for_storage,
                                     branch=pr_source_branch)
    else:
        logger.info("GitHub (通用审查): 所有被检查的文件均未发现问题。")
        no_issues_text = f"AI General Code Review 已完成，对 {len(file_data_list)} 个文件的检查均未发现主要问题或无审查建议。"
        add_github_pr_general_comment(owner, repo_name, pull_number, access_token, no_issues_text)
        _save_review_results_and_log(vcs_type='github_general', identifier=repo_full_name, pr_mr_id=str(pull_number),
                                     commit_sha=head_sha, review_json_string=json.dumps([]), branch=pr_source_branch
                                     # Save empty list
                                     )

    if app_configs.get("WECOM_BOT_WEBHOOK_URL"):
        logger.info("GitHub (通用审查): 正在发送摘要通知到企业微信机器人...")
        num_files_with_issues = len(files_with_issues_details)
        total_files_checked = len(file_data_list)

        summary_line = f"AI General Code Review 已完成。在 {total_files_checked} 个已检查文件中，发现 {num_files_with_issues} 个文件可能存在问题。"
        if num_files_with_issues == 0:
            summary_line = f"AI General Code Review 已完成。所有 {total_files_checked} 个已检查文件均未发现主要问题。"

        summary_content = f"""**AI通用代码审查完成 (GitHub)**

> 仓库: [{repo_full_name}]({repo_web_url})
> PR: [{pr_title}]({pr_html_url}) (#{pull_number})
> 分支: `{pr_source_branch}` → `{pr_target_branch}`

{summary_line}
"""
        # send_to_wecom_bot(summary_content) # 旧调用
        send_notifications(summary_content)  # 新调用

    if head_sha:
        mark_commit_as_processed('github_general', repo_full_name, str(pull_number), head_sha)

    # 添加最终总结评论
    final_comment_text = get_final_summary_comment_text()
    add_github_pr_general_comment(owner, repo_name, pull_number, access_token, final_comment_text)


def _process_gitlab_general_payload(access_token, project_id_str, mr_iid, mr_attrs, final_position_info,
                                    head_sha_payload, current_commit_sha_for_ops, project_name_from_payload,
                                    project_web_url, mr_title, mr_url):
    """实际处理 GitLab 通用审查的核心逻辑。"""
    logger.info("GitLab (通用审查): 正在获取 MR 数据 (diffs 和文件内容)...")
    file_data_list = get_gitlab_mr_data_for_general_review(project_id_str, mr_iid, access_token, mr_attrs,
                                                           final_position_info)

    if file_data_list is None:
        logger.warning("GitLab (通用审查): 获取 MR 数据失败。中止审查。")
        return
    if not file_data_list:
        logger.info("GitLab (通用审查): 未检测到文件变更或数据。无需审查。")
        _save_review_results_and_log(  # 保存空列表表示已处理且无内容
            vcs_type='gitlab_general', identifier=project_id_str, pr_mr_id=str(mr_iid),
            commit_sha=current_commit_sha_for_ops, review_json_string=json.dumps([]),
            project_name_for_gitlab=project_name_from_payload, branch=mr_attrs.get('source_branch'))
        return

    aggregated_general_reviews_for_storage = []
    files_with_issues_details = []  # {file_path: str, issues_text: str}

    logger.info(
        f'GitLab (通用审查): 将对 {len(file_data_list)} 个文件逐一发送给 {app_configs.get("OPENAI_MODEL", "gpt-4o")} 进行审查...')

    for file_item in file_data_list:
        current_file_path = file_item.get("file_path", "Unknown File")
        logger.info(f"GitLab (通用审查): 正在对文件 {current_file_path} 进行 LLM 审查...")

        rag_payload = rag_service.build_rag_context_for_file(
            "gitlab_general",
            project_id_str,
            current_file_path,
            {"context": {"old": file_item.get("old_content"), "new": file_item.get("diff_text")}, "changes": []},
            top_k=int(app_configs.get("RAG_TOP_K", 5) or 5),
        )
        if rag_payload.get("enabled") and rag_payload.get("context"):
            file_item = dict(file_item)
            file_item["rag"] = {
                "sources": rag_payload.get("sources") or [],
                "context": rag_payload.get("context") or "",
            }

        review_text_for_file = get_openai_code_review_general(file_item)

        logger.info(f"GitLab (通用审查): 文件 {current_file_path} 的 LLM 原始输出:\n{review_text_for_file}")

        if review_text_for_file and review_text_for_file.strip() and "此文件未发现问题" not in review_text_for_file and "没有修改建议" not in review_text_for_file and "OpenAI client is not available" not in review_text_for_file and "Error serializing input data" not in review_text_for_file:

            logger.info(f"GitLab (通用审查): 文件 {current_file_path} 发现问题。正在添加评论...")
            comment_text_for_mr = f"**AI 审查意见 (文件: `{current_file_path}`)**\n\n{review_text_for_file}"
            add_gitlab_mr_general_comment(project_id_str, mr_iid, access_token, comment_text_for_mr)

            files_with_issues_details.append({"file": current_file_path, "issues": review_text_for_file})

            review_wrapper_for_file = {"file": current_file_path, "lines": {"old": None, "new": None},
                                       "category": "general Review", "severity": "INFO",
                                       "analysis": review_text_for_file, "suggestion": "请参考上述分析。"}
            used_sources = rag_payload.get("sources") or []
            if used_sources:
                review_wrapper_for_file["rag_sources"] = used_sources
            aggregated_general_reviews_for_storage.append(review_wrapper_for_file)
        else:
            logger.info(f"GitLab (通用审查): 文件 {current_file_path} 未发现问题、审查意见为空或指示无问题。")

    # After processing all files
    if aggregated_general_reviews_for_storage:
        review_json_string_for_storage = json.dumps(aggregated_general_reviews_for_storage)
        _save_review_results_and_log(vcs_type='gitlab_general', identifier=project_id_str, pr_mr_id=str(mr_iid),
                                     commit_sha=current_commit_sha_for_ops,
                                     review_json_string=review_json_string_for_storage,
                                     project_name_for_gitlab=project_name_from_payload,
                                     branch=mr_attrs.get('source_branch'))
    else:
        logger.info("GitLab (通用审查): 所有被检查的文件均未发现问题。")
        no_issues_text = f"AI General Code Review 已完成，对 {len(file_data_list)} 个文件的检查均未发现主要问题或无审查建议。"
        add_gitlab_mr_general_comment(project_id_str, mr_iid, access_token, no_issues_text)
        _save_review_results_and_log(vcs_type='gitlab_general', identifier=project_id_str, pr_mr_id=str(mr_iid),
                                     commit_sha=current_commit_sha_for_ops, review_json_string=json.dumps([]),
                                     # Save empty list
                                     project_name_for_gitlab=project_name_from_payload,
                                     branch=mr_attrs.get('source_branch'))

    if app_configs.get("WECOM_BOT_WEBHOOK_URL"):
        logger.info("GitLab (通用审查): 正在发送摘要通知到企业微信机器人...")
        num_files_with_issues = len(files_with_issues_details)
        total_files_checked = len(file_data_list)

        summary_line = f"AI General Code Review 已完成。在 {total_files_checked} 个已检查文件中，发现 {num_files_with_issues} 个文件可能存在问题。"
        if num_files_with_issues == 0:
            summary_line = f"AI General Code Review 已完成。所有 {total_files_checked} 个已检查文件均未发现主要问题。"

        mr_source_branch = mr_attrs.get('source_branch')
        mr_target_branch = mr_attrs.get('target_branch')
        summary_content = f"""**AI通用代码审查完成 (GitLab)**

> 项目: [{project_name_from_payload or project_id_str}]({project_web_url})
> MR: [{mr_title}]({mr_url}) (!{mr_iid}) 
> 分支: `{mr_source_branch}` → `{mr_target_branch}`

{summary_line}
"""
        send_notifications(summary_content)

    if current_commit_sha_for_ops:
        mark_commit_as_processed('gitlab_general', project_id_str, str(mr_iid), current_commit_sha_for_ops)

    # 添加最终总结评论
    final_comment_text = get_final_summary_comment_text()
    add_gitlab_mr_general_comment(project_id_str, mr_iid, access_token, final_comment_text)
