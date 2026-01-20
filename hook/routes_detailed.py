import json
import logging
from flask import request, abort, jsonify

from config.core_config import mark_commit_as_processed, app_configs
from hook.push_process import get_final_summary_comment_text
from hook.helpers import _save_review_results_and_log
from services.llm_service import get_openai_code_review, get_openai_detailed_review_for_file, get_openai_client
from services.notification_service import send_notifications
from services.vcs_service import (get_github_pr_changes, add_github_pr_comment, get_gitlab_mr_changes,
                                  add_gitlab_mr_comment, add_github_pr_general_comment,  # Used for final summary
                                  add_gitlab_mr_general_comment  # Used for final summary
                                  )
from config.utils import verify_github_signature, verify_gitlab_signature
logger = logging.getLogger(__name__)


# --- Helper Functions Specific to Detailed Review ---
def _post_no_issues_comment(vcs_type, comment_function, **comment_args_for_func):
    """当没有审查建议时，发表一个通用的“全部通过”评论到 PR/MR。"""
    logger.info(f"{vcs_type.capitalize()}: AI 无审查建议。将发表 '全部通过' 评论。")
    overall_status_file = f"Overall {'PR' if vcs_type == 'github' else 'MR'} Status"
    no_issues_review = {"file": overall_status_file, "severity": "INFO", "category": "General",
                        "analysis": "AI Code Review 已完成，所有检查均已通过，无审查建议。", "suggestion": "Looks good!",
                        "lines": {}# 确保这是一个通用的 PR/MR 评论
                        }
    # comment_function 需要 'review' 作为命名参数
    comment_function(review=no_issues_review, **comment_args_for_func)


def _get_wecom_summary_line(num_reviews, vcs_type):
    """为企业微信通知生成摘要行。"""
    entity_name = "Pull Request" if vcs_type == 'github' else "Merge Request"
    if num_reviews == 0:
        return "AI Code Review 已完成，所有检查均已通过，无审查建议。"
    else:
        return f"AI Code Review 已完成，共生成 {num_reviews} 条审查建议。请前往 {entity_name} 查看详情。"


# --- End Helper Functions --

def _process_github_detailed_payload(access_token, owner, repo_name, pull_number, head_sha, repo_full_name, pr_title,
                                     pr_html_url, repo_web_url, pr_source_branch, pr_target_branch):
    """实际处理 GitHub 详细审查的核心逻辑 (逐文件审查和评论)。"""
    logger.info("GitHub (详细审查): 正在获取并解析 PR 变更...")
    structured_changes = get_github_pr_changes(owner, repo_name, pull_number, access_token)

    if structured_changes is None:
        logger.warning("GitHub (详细审查): 获取或解析 diff 内容失败。中止审查。")
        return
    if not structured_changes:
        logger.info("GitHub (详细审查): 解析后未检测到变更。无需审查。")
        _save_review_results_and_log(vcs_type='github', identifier=repo_full_name, pr_mr_id=str(pull_number),
                                     commit_sha=head_sha, review_json_string=json.dumps([]), branch=pr_source_branch)
        mark_commit_as_processed('github', repo_full_name, str(pull_number), head_sha)
        return

    all_reviews_for_redis = []
    total_comments_posted_successfully = 0

    # 获取 OpenAI 客户端和模型配置一次
    client = get_openai_client()
    if not client:
        logger.error("GitHub (详细审查): OpenAI 客户端不可用。中止审查。")
        # 可以考虑发送一个错误通知或评论
        return
    current_model = app_configs.get("OPENAI_MODEL", "gpt-4o")

    logger.info(f'GitHub (详细审查): 将对 {len(structured_changes)} 个文件逐一发送给 {current_model} 进行审查...')

    for file_path, file_data in structured_changes.items():
        logger.info(f"GitHub (详细审查): 正在处理文件: {file_path}")
        reviews_for_file_list = get_openai_detailed_review_for_file(file_path, file_data, client, current_model)

        if reviews_for_file_list:  # reviews_for_file_list 是一个 Python 列表
            all_reviews_for_redis.extend(reviews_for_file_list)
            logger.info(
                f"GitHub (详细审查): 文件 {file_path} 发现 {len(reviews_for_file_list)} 个问题。正在尝试添加评论...")

            file_comments_added, file_comments_failed = 0, 0
            for review_item in reviews_for_file_list:
                # 确保 review_item 中包含 old_path (如果适用)
                if "old_path" not in review_item and file_data.get("old_path"):
                    review_item["old_path"] = file_data["old_path"]

                success = add_github_pr_comment(owner, repo_name, pull_number, access_token, review_item, head_sha)
                if success:
                    file_comments_added += 1
                    total_comments_posted_successfully += 1
                else:
                    file_comments_failed += 1
            logger.info(
                f"GitHub (详细审查): 文件 {file_path} 评论添加完成: {file_comments_added} 成功, {file_comments_failed} 失败。")
        else:
            logger.info(f"GitHub (详细审查): 文件 {file_path} 未发现问题或审查时出错。")

    # 所有文件处理完毕后
    logger.info("--- GitHub (详细审查): 所有文件处理完毕 ---")
    logger.info(f"总共收集到 {len(all_reviews_for_redis)} 条审查意见用于存储。")

    # 保存所有收集到的审查结果到 Redis
    final_review_json_for_redis = "[]"
    if all_reviews_for_redis:
        try:
            final_review_json_for_redis = json.dumps(all_reviews_for_redis, ensure_ascii=False, indent=2)
        except TypeError as e:
            logger.error(
                f"GitHub (详细审查): 序列化最终审查列表到 JSON 时出错: {e}")  # 保留 final_review_json_for_redis 为 "[]"

    _save_review_results_and_log(vcs_type='github', identifier=repo_full_name, pr_mr_id=str(pull_number),
                                 commit_sha=head_sha, review_json_string=final_review_json_for_redis,
                                 branch=pr_source_branch)

    # 如果没有任何评论被成功发布 (或 all_reviews_for_redis 为空)
    if not all_reviews_for_redis:  # 或者 total_comments_posted_successfully == 0
        _post_no_issues_comment(vcs_type='github', comment_function=add_github_pr_comment, owner=owner,
                                repo_name=repo_name, pull_number=pull_number, access_token=access_token,
                                head_sha=head_sha)

    # 发送企业微信通知
    if app_configs.get("WECOM_BOT_WEBHOOK_URL") or app_configs.get("CUSTOM_WEBHOOK_URL"):
        logger.info("GitHub (详细审查): 正在发送摘要通知...")
        review_summary_line = _get_wecom_summary_line(len(all_reviews_for_redis), 'github')
        summary_content = f"""**AI代码审查完成 (GitHub)**

> 仓库: [{repo_full_name}]({repo_web_url})
> PR: [{pr_title}]({pr_html_url}) (#{pull_number})
> 分支: `{pr_source_branch}` → `{pr_target_branch}`

{review_summary_line}
"""
        # send_to_wecom_bot(summary_content) # 旧调用 - 已被 send_notifications 替代
        send_notifications(summary_content)  # 新调用

    if head_sha:
        mark_commit_as_processed('github', repo_full_name, str(pull_number), head_sha)
    else:
        logger.warning(f"警告: GitHub (详细审查) PR {repo_full_name}#{pull_number} 的 head_sha 为空。无法标记为已处理。")

    final_comment_text = get_final_summary_comment_text()
    add_github_pr_general_comment(owner, repo_name, pull_number, access_token, final_comment_text)


def _process_gitlab_detailed_payload(access_token, project_id_str, mr_iid, head_sha_payload, project_data, mr_attrs,
                                     project_web_url, mr_title, mr_url, project_name_from_payload):
    """实际处理 GitLab 详细审查的核心逻辑。"""
    logger.info("GitLab (详细审查): 正在获取并解析 MR 变更...")
    structured_changes, position_info = get_gitlab_mr_changes(project_id_str, mr_iid, access_token)

    if position_info is None: position_info = {}
    if head_sha_payload and not position_info.get("head_sha"):
        position_info["head_sha"] = head_sha_payload
        logger.info(f"GitLab (详细审查): 使用来自 webhook 负载的 head_sha: {head_sha_payload}")
    if not all(k in position_info for k in ["base_sha", "start_sha", "head_sha"]):
        logger.warning("GitLab (详细审查): 警告: 缺少用于精确定位评论的关键提交 SHA 信息。")

    if structured_changes is None:
        logger.warning("GitLab (详细审查): 获取或解析 diff 内容失败。中止审查。")
        return
    if not structured_changes:
        logger.info("GitLab (详细审查): 解析后未检测到变更。无需审查。")
        _save_review_results_and_log(vcs_type='gitlab', identifier=project_id_str, pr_mr_id=str(mr_iid),
                                     commit_sha=head_sha_payload, review_json_string=json.dumps([]),
                                     project_name_for_gitlab=project_name_from_payload,
                                     branch=mr_attrs.get('source_branch'))
        mark_commit_as_processed('gitlab', project_id_str, str(mr_iid), head_sha_payload)
        return

    logger.info(f'GitLab (详细审查): 正在发送变更给 {app_configs.get("OPENAI_MODEL", "gpt-4o")} 进行审查...')
    review_result_json = get_openai_code_review(structured_changes)

    logger.info("--- GitLab (详细审查): AI 代码审查结果 (JSON) ---")
    logger.info(f"{review_result_json}")
    logger.info("--- GitLab (详细审查) 审查 JSON 结束 ---")

    current_commit_sha_for_saving = head_sha_payload
    if not current_commit_sha_for_saving and position_info and position_info.get("head_sha"):
        current_commit_sha_for_saving = position_info.get("head_sha")
        logger.info(
            f"GitLab (详细审查): 使用来自 position_info 的 head_sha ({current_commit_sha_for_saving}) 进行后续操作。")

    _save_review_results_and_log(vcs_type='gitlab', identifier=project_id_str, pr_mr_id=str(mr_iid),
                                 commit_sha=current_commit_sha_for_saving, review_json_string=review_result_json,
                                 project_name_for_gitlab=project_name_from_payload,
                                 branch=mr_attrs.get('source_branch'))

    reviews = []
    try:
        parsed_data = json.loads(review_result_json)
        if isinstance(parsed_data, list): reviews = parsed_data
        logger.info(f"GitLab (详细审查): 从 JSON 成功解析 {len(reviews)} 个审查项。")
    except json.JSONDecodeError as e:
        logger.error(f"GitLab (详细审查): 解析审查结果 JSON 时出错: {e}。原始数据: {review_result_json[:500]}")

    if reviews:
        logger.info(f"GitLab (详细审查): 尝试向 MR 添加 {len(reviews)} 条审查评论...")
        comments_added, comments_failed = 0, 0
        for review in reviews:
            if isinstance(review, dict) and "file" in review:
                file_path = review["file"]
                if file_path in structured_changes:
                    review["old_path"] = structured_changes[file_path].get("old_path")
            if isinstance(review, dict):
                success = add_gitlab_mr_comment(project_id_str, mr_iid, access_token, review, position_info)
                if success:
                    comments_added += 1
                else:
                    comments_failed += 1
            else:
                logger.warning(f"GitLab (详细审查): 跳过无效的审查项: {review}");
                comments_failed += 1
        logger.info(f"GitLab (详细审查): 添加评论完成: {comments_added} 成功, {comments_failed} 失败。")
    else:
        _post_no_issues_comment(vcs_type='gitlab', comment_function=add_gitlab_mr_comment, project_id=project_id_str,
                                mr_iid=mr_iid, access_token=access_token, position_info=position_info)

    if app_configs.get("WECOM_BOT_WEBHOOK_URL"):
        logger.info("GitLab (详细审查): 正在发送摘要通知到企业微信机器人...")
        project_name = project_data.get('name', project_id_str)
        mr_source_branch = mr_attrs.get('source_branch')
        mr_target_branch = mr_attrs.get('target_branch')

        review_summary_line = _get_wecom_summary_line(len(reviews), 'gitlab')
        summary_content = f"""**AI代码审查完成 (GitLab)**

> 项目: [{project_name}]({project_web_url})
> MR: [{mr_title}]({mr_url}) (#{mr_iid})
> 分支: `{mr_source_branch}` → `{mr_target_branch}`

{review_summary_line}
"""
        # send_to_wecom_bot(summary_content) # 旧调用
        send_notifications(summary_content)  # 新调用

    if head_sha_payload:
        mark_commit_as_processed('gitlab', project_id_str, str(mr_iid), head_sha_payload)
    elif position_info and position_info.get("head_sha"):
        logger.warning(
            f"警告: GitLab (详细审查) head_sha_payload 为空，使用来自 position_info 的 head_sha 进行标记处理: {position_info.get('head_sha')}")
        mark_commit_as_processed('gitlab', project_id_str, str(mr_iid), position_info.get("head_sha"))

    final_comment_text = get_final_summary_comment_text()
    add_gitlab_mr_general_comment(project_id_str, mr_iid, access_token, final_comment_text)