import base64
import json
import logging
from typing import Optional
from urllib.parse import quote

import requests

from config.core_config import app_configs
from utils.diff_parser import parse_single_file_diff

logger = logging.getLogger(__name__)


def get_github_pr_changes(owner, repo_name, pull_number, access_token):
    """??GitHub API 获取 Pull Request 的变更，并为每个文件解析成结构化数据"""
    if not access_token:
        logger.error(f"错误: 仓库 {owner}/{repo_name} 未配置访问令牌?")
        return None

    current_github_api_url = app_configs.get("GITHUB_API_URL", "https://api.github.com")
    files_url = f"{current_github_api_url}/repos/{owner}/{repo_name}/pulls/{pull_number}/files"
    headers = {"Authorization": f"token {access_token}", "Accept": "application/vnd.github.v3+json"}

    structured_changes = {}

    try:
        logger.info(f"从以下地址获取 PR 文件: {files_url}")
        response = requests.get(files_url, headers=headers, timeout=60)
        response.raise_for_status()
        files_data = response.json()

        if not files_data:
            logger.info(f"PR {owner}/{repo_name}#{pull_number}: no files returned by API.")
            return {}

        logger.info(f"PR {pull_number}: received {len(files_data)} files from API.")

        for file_item in files_data:
            file_patch_text = file_item.get('patch')
            new_path = file_item.get('filename')
            old_path = file_item.get('previous_filename')
            status = file_item.get('status')

            if not file_patch_text and status != 'removed':
                logger.warning(f"警告: 因非删除文件缺少补丁文本而跳过文件项。文?? {new_path}, 状?? {status}")
                continue

            if status == 'removed':
                if not file_patch_text:  # Usually removed files might not have a patch, or it's empty
                    file_changes_data = {"path": new_path,  # new_path is the path of the removed file
                                         "old_path": None,
                                         # No old_path if it's just a removal, unless it was renamed then removed (complex case)
                                         "changes": [{"type": "delete", "old_line": 0, "new_line": None,
                                                      "content": "File removed"}],
                                         "context": {"old": "", "new": ""},
                                         # No context for a fully removed file via this path
                                         "lines_changed": 0  # Or count lines if available from another source
                                         }
                    structured_changes[new_path] = file_changes_data
                    logger.info(f"Marked removed file: {new_path}")
                    continue

            logger.info(f"解析文件 diff: {new_path} (旧路?? {old_path if old_path else 'N/A'}, 状?? {status})")
            try:
                # 使用通用??parse_single_file_diff
                file_parsed_changes = parse_single_file_diff(file_patch_text, new_path, old_path)
                if file_parsed_changes and file_parsed_changes.get("changes"):
                    structured_changes[new_path] = file_parsed_changes
                    logger.info(f"Parsed {new_path}: {len(file_parsed_changes['changes'])} changes")
                elif status == 'added' and not file_parsed_changes.get("changes"):  # Empty new file
                    logger.info(f"New file with no diff content: {new_path}")
                elif status == 'removed' and not file_parsed_changes.get(
                        "changes"):  # File removed, patch might be empty
                    logger.info(f"Removed file with empty diff: {new_path}")
                else:  # Other statuses or unexpected empty changes
                    logger.info(f"未从 {new_path} ??diff 中解析出变更。状?? {status}")
            except Exception as parse_e:
                logger.exception(f"解析文件 {new_path} ??diff 时出??")

        if not structured_changes:
            logger.info(f"PR {owner}/{repo_name}#{pull_number}: no parseable changes found.")

    except requests.exceptions.RequestException as e:
        logger.error(f"??GitHub API ({files_url}) 获取数据时出?? {e}")
        if 'response' in locals() and response is not None:
            logger.error(f"响应状?? {response.status_code}, 响应?? {response.text[:500]}...")
    except json.JSONDecodeError as json_e:
        logger.error(f"解码来自 GitHub API ({files_url}) ??JSON 响应时出?? {json_e}")
        if 'response' in locals() and response is not None:
            logger.error(f"响应文本: {response.text[:500]}...")
    except Exception as e:
        logger.exception(f"获取/解析 {owner}/{repo_name} ??PR {pull_number} ??diff 时发生意外错??")

    return structured_changes


def get_gitlab_mr_changes(project_id, mr_iid, access_token):
    """??GitLab API 获取 Merge Request 的变更，并为每个文件解析成结构化数据"""
    if not access_token:
        logger.error(f"Missing access token for project {project_id}.")
        return None, None

    project_config = app_configs.get(str(project_id), {})
    project_specific_instance_url = project_config.get("instance_url")
    versions_url = f"{project_specific_instance_url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/versions"
    headers = {"PRIVATE-TOKEN": access_token}
    structured_changes = {}
    position_info = None

    try:
        logger.info(f"从以下地址获取 MR 版本: {versions_url}")
        response = requests.get(versions_url, headers=headers, timeout=60)
        response.raise_for_status()
        versions_data = response.json()

        if versions_data:
            latest_version = versions_data[0]
            position_info = {"base_sha": latest_version.get("base_commit_sha"),
                             "start_sha": latest_version.get("start_commit_sha"),
                             "head_sha": latest_version.get("head_commit_sha"), }
            latest_version_id = latest_version.get("id")
            logger.info(f"从最新版??(ID: {latest_version_id}) 提取的位置信?? {position_info}")

            # current_gitlab_instance_url is already defined above using project-specific or global config
            version_detail_url = f"{project_specific_instance_url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/versions/{latest_version_id}"
            logger.info(f"从以下地址获取版本 ID {latest_version_id} 的详细信?? {version_detail_url}")
            version_detail_response = requests.get(version_detail_url, headers=headers, timeout=60)
            version_detail_response.raise_for_status()
            version_detail_data = version_detail_response.json()

            api_diffs = version_detail_data.get('diffs', [])
            logger.info(f"MR version {latest_version_id}: received {len(api_diffs)} diffs from API.")

            for diff_item in api_diffs:
                file_diff_text = diff_item.get('diff')
                new_path = diff_item.get('new_path')
                old_path = diff_item.get('old_path')
                is_renamed = diff_item.get('renamed_file', False)

                if not file_diff_text or not new_path:
                    logger.warning(
                        f"警告: 因缺??diff 文本??new_path 而跳??diff 项。项: {diff_item.get('new_path', 'N/A')}")
                    continue

                logger.info(f"解析文件 diff: {new_path} (旧路?? {old_path if is_renamed else 'N/A'})")
                try:
                    # 使用通用??parse_single_file_diff
                    file_parsed_changes = parse_single_file_diff(file_diff_text, new_path,
                                                                 old_path if is_renamed else None)
                    if file_parsed_changes and file_parsed_changes.get("changes"):
                        structured_changes[new_path] = file_parsed_changes
                        logger.info(f"Parsed {new_path}: {len(file_parsed_changes['changes'])} changes")
                    else:
                        logger.info(f"No changes parsed from diff for {new_path}")
                except Exception as parse_e:
                    logger.exception(f"解析文件 {new_path} ??diff 时出??")

            if not structured_changes:
                logger.info(f"MR {project_id}#{mr_iid}: no parseable changes found.")
        else:
            logger.info(f"MR {project_id}#{mr_iid}: no versions found in initial response.")

    except requests.exceptions.RequestException as e:
        request_url = locals().get('version_detail_url') or locals().get('versions_url', 'GitLab API')
        error_response = locals().get('version_detail_response') or locals().get('response')
        logger.error(f"??{request_url} 获取数据时出?? {e}")
        if error_response is not None:
            logger.error(f"响应状?? {error_response.status_code}, 响应?? {error_response.text[:500]}...")
    except json.JSONDecodeError as json_e:
        request_url = locals().get('version_detail_url') or locals().get('versions_url', 'GitLab API')
        error_response = locals().get('version_detail_response') or locals().get('response')
        logger.error(f"解码来自 {request_url} ??JSON 响应时出?? {json_e}")
        if error_response is not None:
            logger.error(f"响应文本: {error_response.text[:500]}...")
    except Exception as e:
        logger.exception(f"获取/解析项目 {project_id} ??MR {mr_iid} ??diff 时发生意外错??")

    return structured_changes, position_info


def _fetch_file_content_from_url(url: str, headers: dict, is_github: bool = False, max_size_bytes: int = None):
    """
    通用辅助函数，用于从给定 URL 获取文件内容??
    GitHub raw URL 直接返回文本。GitHub Contents API ??GitLab Files API 返回 JSON，其中内容为 base64 编码??
    增加??max_size_bytes 参数用于限制通过 API 获取的文件大小??
    """
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()

        if is_github and "application/vnd.github.v3.raw" in headers.get("Accept", ""):  # GitHub raw URL
            # Try to decode as UTF-8, fallback to ISO-8859-1 then skip if fails
            try:
                return response.content.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    return response.content.decode('iso-8859-1')  # Common fallback
                except UnicodeDecodeError:
                    logger.warning(f"Failed to decode content from {url} as UTF-8 or ISO-8859-1.")
                    return None
        else:  # GitHub Contents API or GitLab Files API
            data = response.json()

            # 文件大小检??(适用于返??JSON 并包??size 字段??API)
            file_size = data.get('size')
            if file_size is not None and max_size_bytes is not None and file_size > max_size_bytes:
                logger.warning(f"Skipping {url}: size {file_size} exceeds limit {max_size_bytes} bytes.")
                return f"[Content not fetched: File size ({file_size} bytes) exceeds limit {max_size_bytes} bytes]"

            if data.get("encoding") == "base64" and data.get("content"):
                content_bytes = base64.b64decode(data["content"])
                # Try to decode as UTF-8, fallback to ISO-8859-1 then skip if fails
                try:
                    return content_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        return content_bytes.decode('iso-8859-1')
                    except UnicodeDecodeError:
                        logger.warning(f"Failed to decode base64 content from {url} as UTF-8 or ISO-8859-1.")
                        return None
            elif data.get("content") == "":  # Empty file
                return ""
            else:
                logger.warning(f"??{url} 获取文件内容时未找到 base64 内容或编码。响?? {data}")
                return None
    except Exception as e:
        logger.exception(f"??{url} 获取文件内容时出??")
        return None


def get_github_pr_data_for_general_review(owner: str, repo_name: str, pull_number: int, access_token: str,
                                          pr_data: dict):
    """
    ??GitHub PR 获取粗粒度审查所需的数据：文件列表、每个文件的 diff、旧内容和新内容??
    pr_data ??GitHub PR hook 负载中的 'pull_request' 对象??
    """
    if not access_token:
        logger.error(f"Missing access token for repo {owner}/{repo_name}.")
        return None

    current_github_api_url = app_configs.get("GITHUB_API_URL", "https://api.github.com")
    files_url = f"{current_github_api_url}/repos/{owner}/{repo_name}/pulls/{pull_number}/files"
    base_sha = pr_data.get('base', {}).get('sha')
    headers_files_api = {"Authorization": f"token {access_token}", "Accept": "application/vnd.github.v3+json"}
    headers_content_api = {
        "Authorization": f"token {access_token}", "Accept": "application/vnd.github.v3+json"
    }
    general_review_data = []

    try:
        logger.info(f"Fetching PR file list for review: {files_url}")
        response = requests.get(files_url, headers=headers_files_api, timeout=60)
        response.raise_for_status()
        files_api_data = response.json()

        if not files_api_data:
            logger.info(f"PR {owner}/{repo_name}#{pull_number}: no files returned by API.")
            return []

        for file_item in files_api_data:
            file_path = file_item.get('filename')
            status = file_item.get('status')  # 'added', 'modified', 'removed', 'renamed'
            diff_text = file_item.get('patch', '')
            raw_url = file_item.get('raw_url')  # Content at HEAD
            previous_filename = file_item.get('previous_filename')

            file_data_entry = {"file_path": file_path, "status": status, "diff_text": diff_text, "old_content": None}

            # 获取旧内??(适用??'modified', 'removed', 'renamed')
            path_for_old_content = previous_filename if status == 'renamed' and previous_filename else file_path
            if status in ['modified', 'removed', 'renamed'] and base_sha and path_for_old_content:
                old_content_url = f"{current_github_api_url}/repos/{owner}/{repo_name}/contents/{path_for_old_content}?ref={base_sha}"
                logger.info(f"获取旧内?? {path_for_old_content} (ref: {base_sha}) ??{old_content_url}")
                file_data_entry["old_content"] = _fetch_file_content_from_url(old_content_url, headers_content_api,
                                                                              is_github=False,
                                                                              max_size_bytes=1024 * 1024)

            general_review_data.append(file_data_entry)

    except requests.exceptions.RequestException as e:
        logger.error(f"??GitHub API ({files_url}) 获取粗粒度审查数据时出错: {e}")
        return None  # Indicate error
    except Exception as e:
        logger.exception(f"??{owner}/{repo_name} PR {pull_number} 准备粗粒度审查数据时发生意外错误:")
        return None

    return general_review_data


def get_gitlab_mr_data_for_general_review(project_id: str, mr_iid: int, access_token: str, mr_attrs: dict,
                                          position_info: dict):
    """
    ??GitLab MR 获取粗粒度审查所需的数据：文件列表、每个文件的 diff、旧内容和新内容??
    mr_attrs ??GitLab MR hook 负载中的 'object_attributes'??
    position_info 包含 'base_commit_sha', 'start_commit_sha', 'head_commit_sha'??
    """
    if not access_token:
        logger.error(f"Missing access token for project {project_id}.")
        return None

    project_config = app_configs.get(str(project_id), {})
    project_specific_instance_url = project_config.get("instance_url")
    current_gitlab_instance_url = project_specific_instance_url or app_configs.get("GITLAB_INSTANCE_URL",
                                                                                   "https://gitlab.com")

    base_sha = position_info.get("base_commit_sha")
    head_sha = position_info.get("head_commit_sha")
    if not head_sha:  # Fallback to last_commit from hook payload if not in position_info
        head_sha = mr_attrs.get('last_commit', {}).get('id')

    if not base_sha or not head_sha:
        logger.error(
            f"GitLab MR {project_id}#{mr_iid}: 缺少 base_sha ??head_sha，无法获取文件内容。Base: {base_sha}, Head: {head_sha}")
        return None

    headers = {"PRIVATE-TOKEN": access_token}
    general_review_data = []

    latest_version_id = position_info.get("latest_version_id")  # Assuming this is passed in position_info
    if not latest_version_id:  # Fallback: try to get versions if not pre-fetched
        versions_url = f"{current_gitlab_instance_url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/versions"
        try:
            logger.info(f"Fetching MR versions for review: {versions_url}")
            versions_response = requests.get(versions_url, headers=headers, timeout=30)
            versions_response.raise_for_status()
            versions_data = versions_response.json()
            if versions_data:
                latest_version_id = versions_data[0].get("id")
            else:
                logger.warning(f"MR {project_id}#{mr_iid}: no versions found.")
                return []
        except requests.exceptions.RequestException as e:
            logger.error(f"??GitLab API ({versions_url}) 获取 MR 版本时出?? {e}")
            return None

    version_detail_url = f"{current_gitlab_instance_url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/versions/{latest_version_id}"
    try:
        logger.info(f"Fetching MR version detail for review: {version_detail_url}")
        detail_response = requests.get(version_detail_url, headers=headers, timeout=60)
        detail_response.raise_for_status()
        version_detail_data = detail_response.json()
        api_diffs = version_detail_data.get('diffs', [])

        for diff_item in api_diffs:
            new_path = diff_item.get('new_path')
            old_path = diff_item.get('old_path')
            diff_text = diff_item.get('diff', '')
            is_renamed = diff_item.get('renamed_file', False)
            is_deleted = diff_item.get('deleted_file', False)
            is_new = diff_item.get('new_file', False)

            status = "modified"
            if is_new: status = "added"
            if is_deleted: status = "deleted"
            if is_renamed: status = "renamed"

            file_data_entry = {"file_path": new_path,  # For deleted files, new_path is the path of the deleted file
                               "status": status, "diff_text": diff_text, "old_content": None}

            # Get old content (if not new file)
            path_for_old_content = old_path if old_path else new_path  # If renamed, old_path is correct. If modified, old_path is same as new_path.
            if not is_new and path_for_old_content:
                encoded_old_path = requests.utils.quote(path_for_old_content, safe='')
                old_content_url = f"{current_gitlab_instance_url}/api/v4/projects/{project_id}/repository/files/{encoded_old_path}?ref={base_sha}"
                logger.info(f"获取旧内??(GitLab): {path_for_old_content} (ref: {base_sha})")
                file_data_entry["old_content"] = _fetch_file_content_from_url(old_content_url, headers,
                                                                              max_size_bytes=1024 * 1024)

            general_review_data.append(file_data_entry)
    except Exception as e:
        logger.exception(f"??GitLab MR {project_id}#{mr_iid} 准备粗粒度审查数据时发生意外错误:")
        return None

    return general_review_data


def add_github_pr_comment(owner, repo_name, pull_number, access_token, review, head_sha):
    """??GitHub Pull Request 的特定行添加评论"""
    if not access_token:
        logger.error("Missing access token; cannot add GitHub PR comment.")
        return False
    if not head_sha:
        logger.error("Missing head_sha; cannot add GitHub PR comment.")
        return False

    current_github_api_url = app_configs.get("GITHUB_API_URL", "https://api.github.com")
    comment_url = f"{current_github_api_url}/repos/{owner}/{repo_name}/pulls/{pull_number}/comments"
    headers = {"Authorization": f"token {access_token}", "Accept": "application/vnd.github.v3+json",
               "Content-Type": "application/json"}

    body = f"""**AI Review [{review.get('severity', 'N/A').upper()}]**: {review.get('category', 'General')}

**分析**: {review.get('analysis', 'N/A')}

**建议**:
```suggestion
{review.get('suggestion', 'N/A')}
```
"""

    lines_info = review.get("lines", {})
    file_path = review.get("file")

    if not file_path:
        logger.warning("Skipping review comment: missing file path.")
        return False

    payload = {"body": body, "commit_id": head_sha, "path": file_path, }

    line_comment_possible = False
    if lines_info and lines_info.get("new") is not None:
        payload["line"] = lines_info["new"]
        line_comment_possible = True
        target_desc = f"file {file_path} line {lines_info['new']}"

    if not line_comment_possible:
        current_github_api_url = app_configs.get("GITHUB_API_URL", "https://api.github.com")
        general_comment_url = f"{current_github_api_url}/repos/{owner}/{repo_name}/issues/{pull_number}/comments"
        general_payload = {"body": f"**AI Review Comment (File: {file_path})**\n\n{body}"}
        target_desc = f"针对文件 {file_path} 的通用 PR 评论"
        current_url_to_use = general_comment_url
        current_payload_to_use = general_payload
        logger.info(f"No specific line for {file_path}; posting general PR comment.")
    else:
        current_url_to_use = comment_url
        current_payload_to_use = payload
        logger.info(f"Posting line comment for {target_desc}.")

    try:
        response = requests.post(current_url_to_use, headers=headers, json=current_payload_to_use, timeout=30)
        response.raise_for_status()
        logger.info(f"成功??GitHub PR #{pull_number} ({target_desc}) 添加评论")
        return True
    except requests.exceptions.RequestException as e:
        error_message = f"添加 GitHub 评论 ({target_desc}) 时出?? {e}"
        if 'response' in locals() and response is not None:
            error_message += f" - 状?? {response.status_code} - 响应?? {response.text[:500]}"
        logger.error(error_message)

        if line_comment_possible and current_url_to_use == comment_url:
            logger.warning("Line comment failed; falling back to general PR comment.")
            current_github_api_url = app_configs.get("GITHUB_API_URL", "https://api.github.com")
            general_comment_url = f"{current_github_api_url}/repos/{owner}/{repo_name}/issues/{pull_number}/comments"
            fallback_payload = {"body": f"**(评论原针??{target_desc})**\n\n{body}"}
            try:
                fallback_response = requests.post(general_comment_url, headers=headers, json=fallback_payload,
                                                  timeout=30)
                fallback_response.raise_for_status()
                logger.info("Posted general PR comment after line comment failure.")
                return True
            except Exception as fallback_e:
                fb_error_message = f"添加回退的通用 GitHub 评论时出?? {fallback_e}"
                if 'fallback_response' in locals() and fallback_response is not None:
                    fb_error_message += f" - 状?? {fallback_response.status_code} - 响应?? {fallback_response.text[:500]}"
                logger.error(fb_error_message)
                return False
        return False
    except Exception as e:
        logger.exception(f"添加 GitHub 评论 ({target_desc}) 时发生意外错??")
        return False


def add_gitlab_mr_comment(project_id, mr_iid, access_token, review, position_info):
    """??GitLab Merge Request 的特定行添加评论"""
    if not access_token:
        logger.error("Missing access token; cannot add GitLab MR comment.")
        return False
    if not position_info or not position_info.get("head_sha") or not position_info.get(
            "base_sha") or not position_info.get("start_sha"):
        logger.error(f"错误: 无法添加评论，缺少必要的位置信息 (head_sha/base_sha/start_sha)。得?? {position_info}")
        return False

    project_config = app_configs.get(str(project_id), {})
    project_specific_instance_url = project_config.get("instance_url")

    current_gitlab_instance_url = project_specific_instance_url or app_configs.get("GITLAB_INSTANCE_URL","https://gitlab.com")
    if project_specific_instance_url:
        logger.info(f"项目 {project_id} 的评论使用项目特定的 GitLab 实例 URL: {project_specific_instance_url}")
    else:
        logger.info(f"项目 {project_id} 的评论使用全局 GitLab 实例 URL: {current_gitlab_instance_url}")
    comment_url = f"{current_gitlab_instance_url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/discussions"
    headers = {"PRIVATE-TOKEN": access_token, "Content-Type": "application/json"}

    body = f"""**AI Review [{review.get('severity', 'N/A').upper()}]**: {review.get('category', 'General')}

**分析**: {review.get('analysis', 'N/A')}

**建议**:
```suggestion
{review.get('suggestion', 'N/A')}
```
"""
    position_data = {"base_sha": position_info.get("base_sha"), "start_sha": position_info.get("start_sha"),
                     "head_sha": position_info.get("head_sha"), "position_type": "text", }

    lines_info = review.get("lines", {})
    file_path = review.get("file")
    old_file_path = review.get("old_path")

    if not file_path:
        logger.warning("Skipping review comment: missing file path.")
        return False

    line_comment_possible = False
    if lines_info and lines_info.get("new") is not None:
        position_data["new_path"] = file_path
        position_data["new_line"] = lines_info["new"]
        position_data["old_path"] = old_file_path if old_file_path else file_path
        line_comment_possible = True
        target_desc = f"file {file_path} line {lines_info['new']}"
    elif lines_info and lines_info.get("old") is not None:
        position_data["old_path"] = old_file_path if old_file_path else file_path
        position_data["old_line"] = lines_info["old"]
        position_data["new_path"] = file_path
        line_comment_possible = True
        target_desc = f"文件 {position_data['old_path']} 旧行??{lines_info['old']}"
    else:
        target_desc = f"针对文件 {file_path} 的通用讨论"
        line_comment_possible = False

    if line_comment_possible:
        payload = {"body": body, "position": position_data}
        logger.info(f"尝试??{target_desc} 添加带位置的评论")
    else:
        payload = {"body": f"**AI Review Comment (File: {file_path})**\n\n{body}"}
        logger.info(f"No specific line for {file_path}; posting general MR comment.")

    response_obj = None  # Define response_obj to ensure it's available in except block
    try:
        response_obj = requests.post(comment_url, headers=headers, json=payload, timeout=30)
        response_obj.raise_for_status()
        logger.info(f"成功??GitLab MR {mr_iid} ({target_desc}) 添加评论")
        return True
    except requests.exceptions.RequestException as e:
        error_message = f"添加 GitLab 评论 ({target_desc}) 时出?? {e}"
        if response_obj is not None:  # Check if response_obj was assigned
            error_message += f" - 状?? {response_obj.status_code} - 响应?? {response_obj.text[:500]}"
        logger.error(error_message)

        if line_comment_possible:
            logger.warning("Line comment failed; falling back to general MR comment.")
            fallback_payload = {"body": f"**(评论原针??{target_desc})**\n\n{body}"}
            fallback_response_obj = None
            try:
                fallback_response_obj = requests.post(comment_url, headers=headers, json=fallback_payload, timeout=30)
                fallback_response_obj.raise_for_status()
                logger.info("Posted general MR comment after line comment failure.")
                return True
            except Exception as fallback_e:
                fb_error_message = f"添加回退的通用 GitLab 评论时出?? {fallback_e}"
                if fallback_response_obj is not None:
                    fb_error_message += f" - 状?? {fallback_response_obj.status_code} - 响应?? {fallback_response_obj.text[:500]}"
                logger.error(fb_error_message)
                return False
        return False
    except Exception as e:
        logger.exception(f"添加 GitLab 评论 ({target_desc}) 时发生意外错??")
        return False


def add_github_pr_general_comment(owner: str, repo_name: str, pull_number: int, access_token: str, review_text: str):
    """Add a general GitHub PR comment."""
    if not access_token:
        logger.error("Missing access token; cannot add GitHub general comment.")
        return False
    if not review_text.strip():
        logger.info("Review text is empty; skipping general comment.")
        return True  # Technically successful as there's nothing to post

    current_github_api_url = app_configs.get("GITHUB_API_URL", "https://api.github.com")
    # General PR comments are posted as issue comments
    comment_url = f"{current_github_api_url}/repos/{owner}/{repo_name}/issues/{pull_number}/comments"
    headers = {"Authorization": f"token {access_token}", "Accept": "application/vnd.github.v3+json",
               "Content-Type": "application/json"}
    payload = {"body": review_text}

    try:
        response = requests.post(comment_url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        logger.info(f"Posted general comment on GitHub PR #{pull_number}.")
        return True
    except Exception as e:
        logger.exception(f"添加 GitHub 粗粒度审查评论时发生意外错误:")
        return False


def add_gitlab_mr_general_comment(project_id: str, mr_iid: int, access_token: str, review_text: str):
    """Add a general GitLab MR comment."""
    if not access_token:
        logger.error("Missing access token; cannot add GitLab general comment.")
        return False
    if not review_text.strip():
        logger.info("Review text is empty; skipping general comment.")
        return True

    project_config = app_configs.get(str(project_id), {})
    project_specific_instance_url = project_config.get("instance_url")
    current_gitlab_instance_url = project_specific_instance_url or app_configs.get("GITLAB_INSTANCE_URL","https://gitlab.com")

    # Post as a new discussion (thread) without position for general comments
    comment_url = f"{current_gitlab_instance_url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/discussions"
    headers = {"PRIVATE-TOKEN": access_token, "Content-Type": "application/json"}
    payload = {"body": review_text}

    response_obj = None
    try:
        response_obj = requests.post(comment_url, headers=headers, json=payload, timeout=30)
        response_obj.raise_for_status()
        logger.info(f"Posted general comment on GitLab MR {mr_iid}.")
        return True
    except requests.exceptions.RequestException as e:
        error_message = f"添加 GitLab 粗粒度审查评论时出错: {e}"
        if response_obj is not None:
            error_message += f" - 状?? {response_obj.status_code} - 响应?? {response_obj.text[:500]}"
        logger.error(error_message)
        return False
    except Exception as e:
        logger.exception(f"添加 GitLab 粗粒度审查评论时发生意外错误:")
        return False


def _is_all_zero_sha(sha: str) -> bool:
    return bool(sha) and sha == ("0" * 40)


def get_github_branch_head_sha(owner: str, repo_name: str, branch_name: str, access_token: str) -> Optional[str]:
    if not access_token:
        logger.error("Missing GitHub access token; cannot fetch branch head SHA.")
        return None
    current_github_api_url = app_configs.get("GITHUB_API_URL", "https://api.github.com")
    url = f"{current_github_api_url}/repos/{owner}/{repo_name}/branches/{branch_name}"
    headers = {"Authorization": f"token {access_token}", "Accept": "application/vnd.github.v3+json"}
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        return (data.get("commit") or {}).get("sha")
    except Exception as e:
        logger.error(f"获取 GitHub 分支 head SHA 失败: {owner}/{repo_name}@{branch_name}: {e}")
        return None


def get_github_push_changes(owner: str, repo_name: str, before_sha: str, after_sha: str, access_token: str,
                            created: bool = False, default_branch: Optional[str] = None, max_files: int = 20, ):
    """
    使用 GitHub Compare API 获取 push 的文件变更，并解析为结构??diff（与 PR 详细审查一致）??

    注意：GitHub push 新建分支??before 可能??40 ??0，此时优先用 default_branch ??head 作为 base??
    """
    if not access_token:
        logger.error(f"Missing access token for repo {owner}/{repo_name}.")
        return None

    base_sha = before_sha
    if _is_all_zero_sha(before_sha) or created:
        if default_branch:
            resolved_base = get_github_branch_head_sha(owner, repo_name, default_branch, access_token)
            if resolved_base:
                base_sha = resolved_base
        if _is_all_zero_sha(base_sha):
            logger.warning(
                f"GitHub Push: before 为全 0 且无法解??default_branch base，跳??diff 获取 ({owner}/{repo_name})")
            return {}

    current_github_api_url = app_configs.get("GITHUB_API_URL", "https://api.github.com")
    compare_url = f"{current_github_api_url}/repos/{owner}/{repo_name}/compare/{base_sha}...{after_sha}"
    headers = {"Authorization": f"token {access_token}", "Accept": "application/vnd.github.v3+json"}

    structured_changes = {}
    try:
        logger.info(f"GitHub Push: 获取 compare 文件列表: {compare_url}")
        resp = requests.get(compare_url, headers=headers, timeout=60)
        resp.raise_for_status()
        compare_data = resp.json()
        files_data = compare_data.get("files") or []

        for file_item in files_data[: max_files if max_files and max_files > 0 else len(files_data)]:
            file_patch_text = file_item.get("patch")
            new_path = file_item.get("filename")
            old_path = file_item.get("previous_filename")
            status = file_item.get("status")

            if not new_path:
                continue
            if not file_patch_text and status != "removed":
                logger.warning(f"GitHub Push: 跳过??patch 文件: {new_path} (status={status})")
                continue

            if status == "removed" and not file_patch_text:
                structured_changes[new_path] = {"path": new_path, "old_path": None,
                                                "changes": [{"type": "delete", "old_line": 0, "new_line": None,
                                                             "content": "File removed"}],
                                                "context": {"old": "", "new": ""}, "lines_changed": 0, }
                continue

            try:
                parsed = parse_single_file_diff(file_patch_text or "", new_path, old_path)
                if parsed and parsed.get("changes"):
                    structured_changes[new_path] = parsed
            except Exception:
                logger.exception(f"GitHub Push: 解析 diff 失败: {new_path}")

        return structured_changes
    except Exception:
        logger.exception("GitHub Push: failed to fetch/parse compare data.")
        return None


def add_github_commit_comment(owner: str, repo_name: str, commit_sha: str, access_token: str, body: str) -> bool:
    """Add a GitHub commit comment."""
    if not access_token:
        logger.error("Missing GitHub access token; cannot add commit comment.")
        return False
    if not body or not body.strip():
        return True
    current_github_api_url = app_configs.get("GITHUB_API_URL", "https://api.github.com")
    url = f"{current_github_api_url}/repos/{owner}/{repo_name}/commits/{commit_sha}/comments"
    headers = {"Authorization": f"token {access_token}", "Accept": "application/vnd.github.v3+json",
               "Content-Type": "application/json", }
    payload = {"body": body}
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        resp.raise_for_status()
        logger.info(f"Posted GitHub commit comment for {commit_sha[:12]}.")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"添加 GitHub commit 评论失败: {e}")
        return False


def get_gitlab_branch_head_sha(project_id_str: str, branch_name: str, access_token: str,
                               instance_url: Optional[str] = None, ) -> Optional[str]:
    if not access_token:
        logger.error("Missing GitLab access token; cannot fetch branch head SHA.")
        return None

    current_gitlab_instance_url = instance_url or app_configs.get("GITLAB_INSTANCE_URL", "https://gitlab.com")
    encoded_branch = quote(branch_name, safe="")
    url = f"{current_gitlab_instance_url}/api/v4/projects/{project_id_str}/repository/branches/{encoded_branch}"
    headers = {"PRIVATE-TOKEN": access_token}
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        return (data.get("commit") or {}).get("id")
    except Exception as e:
        logger.error(f"获取 GitLab 分支 head SHA 失败: {project_id_str}@{branch_name}: {e}")
        return None


def get_gitlab_push_changes(project_id_str: str, before_sha: str, after_sha: str, access_token: str,
                            instance_url: Optional[str] = None, created: bool = False,
                            default_branch: Optional[str] = None,
                            max_files: int = 20, ):
    """
    使用 GitLab Compare API 获取 push 的文件变更，并解析为结构??diff（与 MR 详细审查一致）??

    注意：新建分支时 before 可能为全 0，此时优先用 default_branch ??head 作为 base??
    """
    if not access_token:
        logger.error(f"Missing access token for project {project_id_str}.")
        return None

    base_sha = before_sha
    if _is_all_zero_sha(before_sha) or created:
        if default_branch:
            resolved_base = get_gitlab_branch_head_sha(project_id_str, default_branch, access_token,
                                                       instance_url=instance_url)
            if resolved_base:
                base_sha = resolved_base
        if _is_all_zero_sha(base_sha):
            logger.warning(
                f"GitLab Push: before 为全 0 且无法解??default_branch base，跳??diff 获取 ({project_id_str})")
            return {}

    current_gitlab_instance_url = instance_url or app_configs.get("GITLAB_INSTANCE_URL", "https://gitlab.com")
    url = f"{current_gitlab_instance_url}/api/v4/projects/{project_id_str}/repository/compare"
    headers = {"PRIVATE-TOKEN": access_token}
    params = {"from": base_sha, "to": after_sha}

    structured_changes = {}
    resp = None
    try:
        logger.info(f"GitLab Push: 获取 compare diff: {project_id_str} {base_sha[:12]}...{after_sha[:12]}")
        resp = requests.get(url, headers=headers, params=params, timeout=60)
        resp.raise_for_status()
        compare_data = resp.json()
        diffs = compare_data.get("diffs") or []

        for diff_item in diffs[: max_files if max_files and max_files > 0 else len(diffs)]:
            new_path = diff_item.get("new_path")
            old_path = diff_item.get("old_path")
            diff_text = diff_item.get("diff") or ""
            deleted_file = bool(diff_item.get("deleted_file"))

            if not new_path:
                continue

            if deleted_file and not diff_text.strip():
                structured_changes[new_path] = {"path": new_path, "old_path": old_path,
                                                "changes": [{"type": "delete", "old_line": 0, "new_line": None,
                                                             "content": "File removed"}],
                                                "context": {"old": "", "new": ""}, "lines_changed": 0, }
                continue

            if not diff_text.strip() and not deleted_file:
                logger.warning(f"GitLab Push: 跳过??diff 文件: {new_path}")
                continue

            try:
                parsed = parse_single_file_diff(diff_text, new_path, old_path if old_path != new_path else None)
                if parsed and parsed.get("changes"):
                    structured_changes[new_path] = parsed
            except Exception:
                logger.exception(f"GitLab Push: 解析 diff 失败: {new_path}")

        return structured_changes
    except requests.exceptions.RequestException as e:
        error_message = f"GitLab Push: 获取 compare 数据失败: {e}"
        if resp is not None:
            error_message += f" - 状??{resp.status_code} - 响应 {resp.text[:500]}"
        logger.error(error_message)
        return None
    except Exception:
        logger.exception("GitLab Push: failed to fetch/parse compare data.")
        return None


def add_gitlab_commit_comment(project_id_str: str, commit_sha: str, access_token: str, note: str,
                              instance_url: Optional[str] = None, ) -> bool:
    """Add a GitLab commit comment."""
    if not access_token:
        logger.error("Missing GitLab access token; cannot add commit comment.")
        return False
    if not note or not note.strip():
        return True

    current_gitlab_instance_url = instance_url or app_configs.get("GITLAB_INSTANCE_URL", "https://gitlab.com")
    url = f"{current_gitlab_instance_url}/api/v4/projects/{project_id_str}/repository/commits/{commit_sha}/comments"
    headers = {"PRIVATE-TOKEN": access_token, "Content-Type": "application/json"}
    payload = {"note": note}

    resp = None
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        resp.raise_for_status()
        logger.info(f"Posted GitLab commit comment for {commit_sha[:12]}.")
        return True
    except requests.exceptions.RequestException as e:
        error_message = f"添加 GitLab commit 评论失败: {e}"
        if resp is not None:
            error_message += f" - 状??{resp.status_code} - 响应 {resp.text[:500]}"
        logger.error(error_message)
        return False
