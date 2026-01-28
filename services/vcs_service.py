import logging
from typing import Optional, Dict, List, Any
from urllib.parse import quote

from github import Github, GithubException
from gitlab import Gitlab, GitlabError

from config.core_config import app_configs
from utils.diff_parser import parse_single_file_diff

logger = logging.getLogger(__name__)


class VCSServiceClass:
    """Simplified VCS service using third-party libraries for GitHub and GitLab operations."""

    def __init__(self):
        self.github_clients = {}  # Cache for GitHub clients
        self.gitlab_clients = {}  # Cache for GitLab clients

    def _get_github_client(self, access_token: str, api_url: Optional[str] = None) -> Github:
        """Get or create GitHub client with caching."""
        if access_token not in self.github_clients:
            api_url = str(api_url or app_configs.get("GITHUB_API_URL", "https://api.github.com"))
            self.github_clients[access_token] = Github(login_or_token=access_token, base_url=api_url, timeout=60)
        return self.github_clients[access_token]

    def _get_gitlab_client(self, access_token: str, instance_url: Optional[str] = None) -> Gitlab:
        """Get or create GitLab client with caching."""
        cache_key = f"{instance_url or 'default'}:{access_token}"
        if cache_key not in self.gitlab_clients:
            instance_url = instance_url or app_configs.get("GITLAB_INSTANCE_URL", "https://gitlab.com")
            self.gitlab_clients[cache_key] = Gitlab(url=instance_url, private_token=access_token, timeout=60)
        return self.gitlab_clients[cache_key]

    def get_github_pr_changes(self, owner: str, repo_name: str, pull_number: int, access_token: str) -> Dict[str, Any]:
        """Get GitHub PR changes using PyGithub."""
        if not access_token:
            logger.error(f"Missing access token for repo {owner}/{repo_name}")
            return {}
        github = self._get_github_client(access_token)
        repo = github.get_repo(f"{owner}/{repo_name}")
        pr = repo.get_pull(pull_number)

        structured_changes = {}

        for file in pr.get_files():
            file_patch_text = file.patch
            new_path = file.filename
            old_path = file.previous_filename
            status = file.status

            if not file_patch_text and status != 'removed':
                logger.warning(f"Skipping file without patch: {new_path} (status: {status})")
                continue

            if status == 'removed' and not file_patch_text:
                structured_changes[new_path] = {"path": new_path, "old_path": None, "changes": [
                    {"type": "delete", "old_line": 0, "new_line": None, "content": "File removed"}],
                                                "context": {"old": "", "new": ""}, "lines_changed": 0}
                continue

            try:
                parsed_changes = parse_single_file_diff(file_patch_text, new_path, old_path)
                if parsed_changes and parsed_changes.get("changes"):
                    structured_changes[new_path] = parsed_changes
                    logger.info(f"Parsed {new_path}: {len(parsed_changes['changes'])} changes")
            except Exception as e:
                logger.exception(f"Failed to parse diff for {new_path}")

        return structured_changes

    def get_gitlab_mr_changes(self, project_id: str, mr_iid: int, access_token: str) -> tuple[
        Dict[str, Any], Optional[Dict[str, str]]]:
        """Get GitLab MR changes using python-gitlab."""
        if not access_token:
            logger.error(f"Missing access token for project {project_id}")
            return {}, None

        project_config = app_configs.get(str(project_id), {})
        instance_url = project_config.get("instance_url")
        gl = self._get_gitlab_client(access_token, instance_url)

        project = gl.projects.get(project_id)
        mr = project.mergerequests.get(mr_iid)

        # Get latest version
        versions = mr.versions.list()
        if not versions:
            logger.info(f"No versions found for MR {mr_iid}")
            return {}, None

        latest_version = versions[0]
        position_info = {"base_sha": latest_version.base_commit_sha, "start_sha": latest_version.start_commit_sha,
                         "head_sha": latest_version.head_commit_sha}

        # Get detailed diff
        version_detail = mr.versions.get(latest_version.id)
        structured_changes = {}

        for diff_item in version_detail.diffs:
            file_diff_text = diff_item.get('diff')
            new_path = diff_item.get('new_path')
            old_path = diff_item.get('old_path')

            if not file_diff_text or not new_path:
                logger.warning(f"Skipping diff without text or path: {new_path}")
                continue

            try:
                parsed_changes = parse_single_file_diff(file_diff_text, new_path, old_path)
                if parsed_changes and parsed_changes.get("changes"):
                    structured_changes[new_path] = parsed_changes
                    logger.info(f"Parsed {new_path}: {len(parsed_changes['changes'])} changes")
            except Exception as e:
                logger.exception(f"Failed to parse diff for {new_path}")

        return structured_changes, position_info

    def get_github_pr_data_for_general_review(self, owner: str, repo_name: str, pull_number: int, access_token: str,
                                              pr_data: dict) -> List[Dict[str, Any]]:
        """Get GitHub PR data for general review."""
        if not access_token:
            logger.error(f"Missing access token for repo {owner}/{repo_name}")
            return []

        github = self._get_github_client(access_token)
        repo = github.get_repo(f"{owner}/{repo_name}")
        pr = repo.get_pull(pull_number)
        base_sha = pr_data.get('base', {}).get('sha')

        general_review_data = []

        for file in pr.get_files():
            file_path = file.filename
            status = file.status
            diff_text = file.patch or ''

            file_data_entry = {"file_path": file_path, "status": status, "diff_text": diff_text,
                               "old_content": None}

            # Get old content for modified/removed/renamed files
            path_for_old_content = file.previous_filename if status == 'renamed' and file.previous_filename else file_path
            if status in ['modified', 'removed', 'renamed'] and base_sha and path_for_old_content:
                try:
                    old_file_content = repo.get_contents(path_for_old_content, ref=base_sha)
                    if old_file_content:
                        # Handle both ContentFile and list of ContentFile cases
                        if isinstance(old_file_content, list):
                            old_file_content = old_file_content[0]
                        if hasattr(old_file_content, 'content') and old_file_content.content:
                            import base64
                            file_data_entry["old_content"] = base64.b64decode(old_file_content.content).decode(
                                'utf-8')
                        elif hasattr(old_file_content, 'decoded_content'):
                            file_data_entry["old_content"] = old_file_content.decoded_content.decode('utf-8')
                except Exception as e:
                    logger.warning(f"Failed to get old content for {path_for_old_content}: {e}")

            general_review_data.append(file_data_entry)

        return general_review_data

    def get_gitlab_mr_data_for_general_review(self, project_id: str, mr_iid: int, access_token: str, mr_attrs: dict,
                                              position_info: dict) -> List[Dict[str, Any]]:
        """Get GitLab MR data for general review."""
        if not access_token:
            logger.error(f"Missing access token for project {project_id}")
            return []

        project_config = app_configs.get(str(project_id), {})
        instance_url = project_config.get("instance_url")
        gl = self._get_gitlab_client(access_token, instance_url)

        project = gl.projects.get(project_id)
        base_sha = position_info.get("base_commit_sha")
        head_sha = position_info.get("head_commit_sha") or mr_attrs.get('last_commit', {}).get('id')

        if not base_sha or not head_sha:
            logger.error(f"Missing base or head SHA for MR {mr_iid}")
            return []

        # Get MR and its diffs
        mr = project.mergerequests.get(mr_iid)
        latest_version_id = position_info.get("latest_version_id") if position_info else None

        if not latest_version_id:
            versions = mr.versions.list()
            if versions:
                latest_version_id = versions[0].id

        if latest_version_id:
            version_detail = mr.versions.get(latest_version_id)
            diffs = version_detail.diffs
        else:
            diffs = mr.changes().get('changes', [])

        general_review_data = []

        for diff_item in diffs:
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

            file_data_entry = {"file_path": new_path, "status": status, "diff_text": diff_text, "old_content": None}

            # Get old content if not new file
            path_for_old_content = old_path if old_path else new_path
            if not is_new and path_for_old_content:
                try:
                    encoded_path = quote(path_for_old_content, safe='')
                    old_file = project.files.get(file_path=encoded_path, ref=base_sha)
                    if old_file:
                        file_data_entry["old_content"] = old_file.decode().decode('utf-8')
                except Exception as e:
                    logger.warning(f"Failed to get old content for {path_for_old_content}: {e}")

            general_review_data.append(file_data_entry)

        return general_review_data

    def add_github_pr_comment(self, owner: str, repo_name: str, pull_number: int, access_token: str,
                              review: Dict[str, Any], head_sha: str) -> bool:
        """Add GitHub PR comment using PyGithub."""
        if not access_token or not head_sha:
            logger.error("Missing access token or head SHA")
            return False

        github = self._get_github_client(access_token)
        repo = github.get_repo(f"{owner}/{repo_name}")
        pr = repo.get_pull(pull_number)

        body = self._format_review_comment(review)
        file_path = review.get("file")
        lines_info = review.get("lines", {})

        if not file_path:
            logger.warning("Missing file path for review comment")
            return False

        # Try to add line comment first
        if lines_info and lines_info.get("new") is not None:
            try:
                commit = repo.get_commit(head_sha)
                pr.create_review_comment(body=body, commit=commit, path=file_path, line=lines_info["new"])
                logger.info(f"Added line comment to PR #{pull_number} for {file_path}")
                return True
            except Exception as e:
                logger.warning(f"Line comment failed, falling back to general comment: {e}")

        # Fallback to general comment
        pr.create_issue_comment(f"**AI Review Comment (File: {file_path})**\n\n{body}")
        logger.info(f"Added general comment to PR #{pull_number} for {file_path}")
        return True

    def add_gitlab_mr_comment(self, project_id: str, mr_iid: int, access_token: str, review: Dict[str, Any],
                              position_info: Dict[str, str]) -> bool:
        """Add GitLab MR comment using python-gitlab."""
        if not access_token or not position_info or not position_info.get("head_sha"):
            logger.error("Missing required parameters for GitLab MR comment")
            return False

        project_config = app_configs.get(str(project_id), {})
        instance_url = project_config.get("instance_url")
        gl = self._get_gitlab_client(access_token, instance_url)

        project = gl.projects.get(project_id)
        mr = project.mergerequests.get(mr_iid)

        body = self._format_review_comment(review)
        file_path = review.get("file")
        old_file_path = review.get("old_path")
        lines_info = review.get("lines", {})

        if not file_path:
            logger.warning("Missing file path for review comment")
            return False

        # Try to add position-based comment
        if lines_info and (lines_info.get("new") is not None or lines_info.get("old") is not None):
            try:
                position_data = {"base_sha": position_info["base_sha"], "start_sha": position_info["start_sha"],
                                 "head_sha": position_info["head_sha"], "position_type": "text",
                                 "new_path": file_path, "old_path": old_file_path if old_file_path else file_path}

                if lines_info.get("new") is not None:
                    position_data["new_line"] = lines_info["new"]
                if lines_info.get("old") is not None:
                    position_data["old_line"] = lines_info["old"]

                mr.discussions.create({"body": body, "position": position_data})
                logger.info(f"Added position comment to MR {mr_iid} for {file_path}")
                return True
            except Exception as e:
                logger.warning(f"Position comment failed, falling back to general comment: {e}")

        # Fallback to general discussion
        mr.discussions.create({"body": f"**AI Review Comment (File: {file_path})**\n\n{body}"})
        logger.info(f"Added general comment to MR {mr_iid} for {file_path}")
        return True

    def add_github_pr_general_comment(self, owner: str, repo_name: str, pull_number: int, access_token: str,
                                      review_text: str) -> bool:
        """Add general GitHub PR comment."""
        if not access_token:
            logger.error("Missing access token")
            return False
        if not review_text.strip():
            return True

        github = self._get_github_client(access_token)
        repo = github.get_repo(f"{owner}/{repo_name}")
        pr = repo.get_pull(pull_number)

        pr.create_issue_comment(review_text)
        logger.info(f"Added general comment to PR #{pull_number}")
        return True

    def add_gitlab_mr_general_comment(self, project_id: str, mr_iid: int, access_token: str, review_text: str) -> bool:
        """Add general GitLab MR comment."""
        if not access_token:
            logger.error("Missing access token")
            return False
        if not review_text.strip():
            return True

        project_config = app_configs.get(str(project_id), {})
        instance_url = project_config.get("instance_url")
        gl = self._get_gitlab_client(access_token, instance_url)

        project = gl.projects.get(project_id)
        mr = project.mergerequests.get(mr_iid)

        mr.discussions.create({"body": review_text})
        logger.info(f"Added general comment to MR {mr_iid}")
        return True

    def get_github_branch_head_sha(self, owner: str, repo_name: str, branch_name: str, access_token: str) -> Optional[
        str]:
        """Get GitHub branch head SHA."""
        if not access_token:
            logger.error("Missing access token")
            return None

        github = self._get_github_client(access_token)
        repo = github.get_repo(f"{owner}/{repo_name}")
        branch = repo.get_branch(branch_name)
        return branch.commit.sha

    def get_gitlab_branch_head_sha(self, project_id: str, branch_name: str, access_token: str,
                                   instance_url: Optional[str] = None) -> Optional[str]:
        """Get GitLab branch head SHA."""
        if not access_token:
            logger.error("Missing access token")
            return None

        gl = self._get_gitlab_client(access_token, instance_url)
        project = gl.projects.get(project_id)
        branch = project.branches.get(branch_name)
        return branch.commit['id']


    def get_github_push_changes(self, owner: str, repo_name: str, before_sha: str, after_sha: str, access_token: str,
                                created: bool = False, default_branch: Optional[str] = None, max_files: int = 20) -> \
            Dict[str, Any]:
        """Get GitHub push changes using compare API via PyGithub."""
        if not access_token:
            logger.error("Missing access token")
            return {}

        github = self._get_github_client(access_token)
        repo = github.get_repo(f"{owner}/{repo_name}")

        # Handle zero SHA case
        base_sha = before_sha
        if self._is_all_zero_sha(before_sha) or created:
            if default_branch:
                try:
                    branch = repo.get_branch(default_branch)
                    base_sha = branch.commit.sha
                except Exception as e:
                    logger.warning(f"Failed to get default branch {default_branch}: {e}")

            if self._is_all_zero_sha(base_sha):
                logger.warning(f"Cannot resolve base SHA for push changes")
                return {}

        comparison = repo.compare(base_sha, after_sha)
        structured_changes = {}

        for file in comparison.files[:max_files if max_files > 0 else len(comparison.files)]:
            file_patch_text = file.patch
            new_path = file.filename
            old_path = file.previous_filename
            status = file.status

            if not new_path:
                continue
            if not file_patch_text and status != "removed":
                logger.warning(f"Skipping file without patch: {new_path}")
                continue

            if status == "removed" and not file_patch_text:
                structured_changes[new_path] = {"path": new_path, "old_path": None, "changes": [
                    {"type": "delete", "old_line": 0, "new_line": None, "content": "File removed"}],
                                                "context": {"old": "", "new": ""}, "lines_changed": 0}
                continue

            try:
                parsed = parse_single_file_diff(file_patch_text, new_path, old_path)
                if parsed and parsed.get("changes"):
                    structured_changes[new_path] = parsed
            except Exception as e:
                logger.exception(f"Failed to parse diff for {new_path}")

        return structured_changes

    def get_gitlab_push_changes(self, project_id: str, before_sha: str, after_sha: str, access_token: str,
                                instance_url: Optional[str] = None, created: bool = False,
                                default_branch: Optional[str] = None, max_files: int = 20) -> Dict[str, Any]:
        """Get GitLab push changes using compare API via python-gitlab."""
        if not access_token:
            logger.error("Missing access token")
            return {}

        gl = self._get_gitlab_client(access_token, instance_url)
        project = gl.projects.get(project_id)

        # Handle zero SHA case
        base_sha = before_sha
        if self._is_all_zero_sha(before_sha) or created:
            if default_branch:
                try:
                    branch = project.branches.get(default_branch)
                    base_sha = branch.commit['id']
                except Exception as e:
                    logger.warning(f"Failed to get default branch {default_branch}: {e}")

            if self._is_all_zero_sha(base_sha):
                logger.warning(f"Cannot resolve base SHA for push changes")
                return {}

        comparison = project.repository_compare(base_sha, after_sha)
        structured_changes = {}
        diffs = comparison.get('diffs', [])

        for diff_item in diffs[:max_files if max_files > 0 else len(diffs)]:
            new_path = diff_item.get("new_path")
            old_path = diff_item.get("old_path")
            diff_text = diff_item.get("diff", "")
            deleted_file = bool(diff_item.get("deleted_file"))

            if not new_path:
                continue

            if deleted_file and not diff_text.strip():
                structured_changes[new_path] = {"path": new_path, "old_path": old_path, "changes": [
                    {"type": "delete", "old_line": 0, "new_line": None, "content": "File removed"}],
                                                "context": {"old": "", "new": ""}, "lines_changed": 0}
                continue

            if not diff_text.strip() and not deleted_file:
                logger.warning(f"Skipping file without diff: {new_path}")
                continue

            try:
                parsed = parse_single_file_diff(diff_text, new_path, old_path if old_path != new_path else None)
                if parsed and parsed.get("changes"):
                    structured_changes[new_path] = parsed
            except Exception as e:
                logger.exception(f"Failed to parse diff for {new_path}")

        return structured_changes

    def add_github_commit_comment(self, owner: str, repo_name: str, commit_sha: str, access_token: str,
                                  body: str) -> bool:
        """Add GitHub commit comment."""
        if not access_token or not body or not body.strip():
            return True

        github = self._get_github_client(access_token)
        repo = github.get_repo(f"{owner}/{repo_name}")
        commit = repo.get_commit(commit_sha)

        commit.create_comment(body)
        logger.info(f"Added commit comment for {commit_sha[:12]}")
        return True


    def add_gitlab_commit_comment(self, project_id: str, commit_sha: str, access_token: str, note: str,
                                  instance_url: Optional[str] = None) -> bool:
        """Add GitLab commit comment."""
        if not access_token or not note or not note.strip():
            return True

        gl = self._get_gitlab_client(access_token, instance_url)
        project = gl.projects.get(project_id)

        project.commits.get(commit_sha).comments.create({"note": note})
        logger.info(f"Added commit comment for {commit_sha[:12]}")
        return True

    def _format_review_comment(self, review: Dict[str, Any]) -> str:
        """Format review data into comment body."""
        return f"""**AI Review [{review.get('severity', 'N/A').upper()}]**: {review.get('category', 'General')}

**分析**: {review.get('analysis', 'N/A')}

**建议**:
```suggestion
{review.get('suggestion', 'N/A')}
```"""

    def _is_all_zero_sha(self, sha: str) -> bool:
        """Check if SHA is all zeros."""
        return bool(sha) and sha == ("0" * 40)


VCSService = VCSServiceClass()