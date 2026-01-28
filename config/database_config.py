import logging

from config.core_config import app_configs

logger = logging.getLogger(__name__)


class DatabaseConfig:
    """PostgreSQL数据库配置"""

    @staticmethod
    def get_database_url() -> str:
        """获取数据库连接URL"""
        # 优先使用DATABASE_URL环境变量

        database_url = app_configs.get('DATABASE_URL')
        if database_url:
            return database_url

        # 使用单独的环境变量构建连接字符串
        db_user = app_configs.get('DB_USER', '')
        db_password = app_configs.get('DB_PASSWORD', '')
        db_host = app_configs.get('DB_HOST', '')
        db_port = app_configs.get('DB_PORT', '')
        db_name = app_configs.get('DB_NAME', '')

        return f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

    @staticmethod
    def get_config():
        """获取数据库配置字典"""
        return {'SQLALCHEMY_DATABASE_URI': DatabaseConfig.get_database_url(), 'SQLALCHEMY_TRACK_MODIFICATIONS': False,
                'SQLALCHEMY_ECHO': app_configs.get('SQLALCHEMY_ECHO', 'false').lower() == 'true'}
