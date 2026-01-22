import json
import logging
from datetime import datetime, timedelta

from config.core_config import app_configs
from db.models import db, ProcessedCommit, ReviewResult, Config

logger = logging.getLogger(__name__)

# 内存中的配置缓存
github_repo_configs = {}
gitlab_project_configs = {}

def init_postgres_config():
    """初始化PostgreSQL配置存储。确保数据库表存在。"""
    try:
        # 创建所有表（如果不存在）
        db.create_all()
        logger.info("PostgreSQL配置存储初始化成功。")
        # 加载配置到内存
        load_configs_from_postgres()
    except Exception as e:
        logger.critical(f"初始化PostgreSQL配置存储失败: {e}")
        raise ValueError(e)

def load_configs_from_postgres():
    """从PostgreSQL加载配置到内存中。"""
    try:
        # 加载GitHub配置
        github_configs = Config.query.filter_by(config_type='github').all()
        for config in github_configs:
            try:
                github_repo_configs[config.key] = json.loads(config.config_json)
            except json.JSONDecodeError as e:
                logger.error(f"解析GitHub配置时出错，键: {config.key}: {e}")

        if github_configs:
            logger.info(f"从PostgreSQL加载了 {len(github_configs)} 个GitHub配置。")

        # 加载GitLab配置
        gitlab_configs = Config.query.filter_by(config_type='gitlab').all()
        for config in gitlab_configs:
            try:
                gitlab_project_configs[config.key] = json.loads(config.config_json)
            except json.JSONDecodeError as e:
                logger.error(f"解析GitLab配置时出错，键: {config.key}: {e}")

        if gitlab_configs:
            logger.info(f"从PostgreSQL加载了 {len(gitlab_configs)} 个GitLab配置。")

    except Exception as e:
        logger.error(f"从PostgreSQL加载配置时发生意外错误: {e}")

def save_config_to_postgres(config_type: str, key: str, config_data: dict):
    """保存配置到PostgreSQL。"""
    try:
        config_json = json.dumps(config_data, ensure_ascii=False)
        config = Config.query.filter_by(config_type=config_type, key=key).first()
        if config:
            config.config_json = config_json
            config.updated_at = datetime.utcnow()
        else:
            config = Config(config_type=config_type, key=key, config_json=config_json)
            db.session.add(config)

        db.session.commit()

        # 更新内存缓存
        if config_type == 'github':
            github_repo_configs[key] = config_data
        elif config_type == 'gitlab':
            gitlab_project_configs[key] = config_data

        logger.info(f"成功保存{config_type}配置: {key}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"保存{config_type}配置到PostgreSQL时出错: {e}")
        raise

def delete_config_from_postgres(config_type: str, key: str):
    """从PostgreSQL删除配置。"""
    try:
        config = Config.query.filter_by(config_type=config_type, key=key).first()
        if config:
            db.session.delete(config)
            db.session.commit()

            # 更新内存缓存
            if config_type == 'github':
                github_repo_configs.pop(key, None)
            elif config_type == 'gitlab':
                gitlab_project_configs.pop(key, None)

            logger.info(f"成功删除{config_type}配置: {key}")
        else:
            logger.warning(f"{config_type}配置不存在: {key}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"删除{config_type}配置从PostgreSQL时出错: {e}")
        raise

def is_commit_processed(vcs_type: str, identifier: str, pr_mr_id: str, commit_sha: str) -> bool:
    """检查指定的commit是否已经被处理过。"""
    if not commit_sha:
        logger.warning(f"警告: commit_sha为空，针对{vcs_type}:{identifier}:{pr_mr_id}。假定未处理。")
        return False

    try:
        processed_commit = ProcessedCommit.query.filter_by(
            vcs_type=vcs_type,
            identifier=identifier,
            pr_mr_id=str(pr_mr_id),
            commit_sha=commit_sha
        ).first()
        return processed_commit is not None
    except Exception as e:
        logger.error(f"检查提交{vcs_type}:{identifier}:{pr_mr_id}:{commit_sha}是否已处理时PostgreSQL出错: {e}")
        return False

def mark_commit_as_processed(vcs_type: str, identifier: str, pr_mr_id: str, commit_sha: str):
    """将指定的commit标记为已处理。"""
    if not commit_sha:
        logger.warning(f"警告: commit_sha为空，针对{vcs_type}:{identifier}:{pr_mr_id}。跳过标记为已处理。")
        return

    try:
        # 检查是否已存在
        existing = ProcessedCommit.query.filter_by(
            vcs_type=vcs_type,
            identifier=identifier,
            pr_mr_id=str(pr_mr_id),
            commit_sha=commit_sha
        ).first()

        if not existing:
            processed_commit = ProcessedCommit(
                vcs_type=vcs_type,
                identifier=identifier,
                pr_mr_id=str(pr_mr_id),
                commit_sha=commit_sha
            )
            db.session.add(processed_commit)
            db.session.commit()
            logger.info(f"成功标记提交{vcs_type}:{identifier}:{pr_mr_id}:{commit_sha}为已处理。")
        else:
            logger.debug(f"提交{vcs_type}:{identifier}:{pr_mr_id}:{commit_sha}已被标记为已处理。")
    except Exception as e:
        db.session.rollback()
        logger.error(f"标记提交{vcs_type}:{identifier}:{pr_mr_id}:{commit_sha}为已处理时PostgreSQL出错: {e}")

def remove_processed_commit_entries_for_pr_mr(vcs_type: str, identifier: str, pr_mr_id: str):
    """当PR/MR关闭或合并时，移除其所有相关的已处理commit条目。"""
    try:
        deleted_count = ProcessedCommit.query.filter_by(
            vcs_type=vcs_type,
            identifier=identifier,
            pr_mr_id=str(pr_mr_id)
        ).delete()
        db.session.commit()

        if deleted_count > 0:
            logger.info(f"为{vcs_type} {identifier} #{pr_mr_id} 从PostgreSQL中总共移除了{deleted_count}个已处理的commit条目。")
        else:
            logger.info(f"在PostgreSQL中未找到与{vcs_type} {identifier} #{pr_mr_id}相关的已处理commit条目。")

        # 同时删除关联的审查结果
        delete_review_results_for_pr_mr(vcs_type, identifier, pr_mr_id)

    except Exception as e:
        db.session.rollback()
        logger.error(f"为{vcs_type} {identifier} #{pr_mr_id}移除已处理的commit条目时发生意外错误: {e}")

def save_review_results(vcs_type: str, identifier: str, pr_mr_id: str, commit_sha: str, review_json_string: str, project_name: str = None, branch: str = None, created_at: str = None):
    """将AI审查结果保存到PostgreSQL。"""
    if not commit_sha:
        logger.warning(f"警告: commit_sha为空，针对{vcs_type}:{identifier}:{pr_mr_id}。跳过保存审查结果。")
        return

    try:
        # 检查是否已存在
        existing = ReviewResult.query.filter_by(
            vcs_type=vcs_type,
            identifier=identifier,
            pr_mr_id=str(pr_mr_id),
            commit_sha=commit_sha
        ).first()

        if existing:
            existing.review_json = review_json_string
            existing.project_name = project_name
            existing.branch = branch
            existing.updated_at = datetime.utcnow()
        else:
            review_result = ReviewResult(
                vcs_type=vcs_type,
                identifier=identifier,
                pr_mr_id=str(pr_mr_id),
                commit_sha=commit_sha,
                review_json=review_json_string,
                project_name=project_name,
                branch=branch
            )
            db.session.add(review_result)

        db.session.commit()

        log_msg = f"成功将{vcs_type} {identifier} #{pr_mr_id} (commit: {commit_sha})的审查结果保存到PostgreSQL。"
        if project_name:
            log_msg += f" 项目名称: {project_name}。"
        logger.info(log_msg)

    except Exception as e:
        db.session.rollback()
        logger.error(f"保存AI审查结果到PostgreSQL时出错 (Commit: {commit_sha}): {e}")

def get_review_results(vcs_type: str, identifier: str, pr_mr_id: str, commit_sha: str = None):
    """从PostgreSQL获取AI审查结果。"""
    try:
        if commit_sha:
            result = ReviewResult.query.filter_by(
                vcs_type=vcs_type,
                identifier=identifier,
                pr_mr_id=str(pr_mr_id),
                commit_sha=commit_sha
            ).first()
            if result:
                return json.loads(result.review_json)
            return None
        else:
            # 获取PR/MR的所有commits的审查结果
            results = ReviewResult.query.filter_by(
                vcs_type=vcs_type,
                identifier=identifier,
                pr_mr_id=str(pr_mr_id)
            ).all()

            decoded_results = {}
            project_name_for_pr_mr = None

            for result in results:
                if result.commit_sha not in decoded_results:
                    try:
                        decoded_results[result.commit_sha] = json.loads(result.review_json)
                        if result.project_name and not project_name_for_pr_mr:
                            project_name_for_pr_mr = result.project_name
                    except json.JSONDecodeError as e:
                        logger.error(f"解析PostgreSQL中的审查结果JSON时出错 (Commit: {result.commit_sha}): {e}")

            final_result = {"commits": decoded_results}
            if project_name_for_pr_mr:
                final_result["project_name"] = project_name_for_pr_mr
            return final_result

    except Exception as e:
        logger.error(f"从PostgreSQL获取AI审查结果时出错: {e}")
        return None if commit_sha else {}

def get_all_reviewed_prs_mrs_keys():
    """获取所有已存储AI审查结果的PR/MR的标识符列表。"""
    try:
        # 获取所有唯一的PR/MR组合
        results = db.session.query(
            ReviewResult.vcs_type,
            ReviewResult.identifier,
            ReviewResult.pr_mr_id,
            db.func.max(ReviewResult.project_name).label('project_name'),
            db.func.max(ReviewResult.branch).label('branch'),
            db.func.max(ReviewResult.created_at).label('created_at'),
            db.func.max(ReviewResult.commit_sha).label('last_commit_sha')
        ).group_by(
            ReviewResult.vcs_type,
            ReviewResult.identifier,
            ReviewResult.pr_mr_id
        ).all()

        identifiers = []
        for result in results:
            vcs_type = result.vcs_type
            identifier = result.identifier
            pr_mr_id = result.pr_mr_id
            project_name = result.project_name or identifier
            branch = result.branch
            created_at = result.created_at.isoformat() if result.created_at else ''
            last_commit_sha = result.last_commit_sha

            # 规范化显示名称中的类型
            if vcs_type == "github_general":
                display_vcs_type_prefix = "GITHUB (General)"
            elif vcs_type == "gitlab_general":
                display_vcs_type_prefix = "GITLAB (General)"
            elif vcs_type == "github":
                display_vcs_type_prefix = "GITHUB (Detailed)"
            elif vcs_type == "gitlab":
                display_vcs_type_prefix = "GITLAB (Detailed)"
            elif vcs_type == "github_push":
                display_vcs_type_prefix = "GITHUB (Push Audit)"
            elif vcs_type == "gitlab_push":
                display_vcs_type_prefix = "GITLAB (Push Audit)"
            else:
                display_vcs_type_prefix = vcs_type.upper()

            identifiers.append({
                "vcs_type": vcs_type,
                "identifier": identifier,
                "pr_mr_id": pr_mr_id,
                "display_name": f"{display_vcs_type_prefix}: {project_name} #{pr_mr_id}",
                "created_at": created_at,
                "branch": branch or '',
                "last_commit_sha": last_commit_sha or '',
                "project_name": project_name
            })

        return identifiers

    except Exception as e:
        logger.error(f"从PostgreSQL获取所有已审查的PR/MR列表时出错: {e}")
        return []

def delete_review_results_for_pr_mr(vcs_type: str, identifier: str, pr_mr_id: str):
    """删除特定PR/MR的所有AI审查结果。"""
    try:
        deleted_count = ReviewResult.query.filter_by(
            vcs_type=vcs_type,
            identifier=identifier,
            pr_mr_id=str(pr_mr_id)
        ).delete()
        db.session.commit()

        if deleted_count > 0:
            logger.info(f"成功从PostgreSQL删除{vcs_type} {identifier} #{pr_mr_id}的AI审查结果 ({deleted_count}条记录)。")
        else:
            logger.info(f"在PostgreSQL中未找到{vcs_type} {identifier} #{pr_mr_id}的AI审查结果以供删除。")

    except Exception as e:
        db.session.rollback()
        logger.error(f"从PostgreSQL删除AI审查结果时出错: {e}")