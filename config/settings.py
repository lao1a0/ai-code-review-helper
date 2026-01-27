"""
Unified configuration settings for AI Code Review Helper
"""
import os
from typing import Dict, Any

# Database Configuration
DATABASE_CONFIG = {
    'SQLALCHEMY_DATABASE_URI': os.environ.get('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/aihelper'),
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SQLALCHEMY_ENGINE_OPTIONS': {
        'pool_size': 10,
        'pool_recycle': 3600,
        'pool_pre_ping': True
    }
}

# Flask Configuration
FLASK_CONFIG = {
    'SECRET_KEY': os.environ.get('SECRET_KEY', 'your-secret-key-change-this'),
    'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16MB max file size
}

# LLM Configuration
LLM_CONFIG = {
    'OPENAI_API_KEY': os.environ.get('OPENAI_API_KEY', ''),
    'OPENAI_MODEL': os.environ.get('OPENAI_MODEL', 'gpt-4o'),
    'OPENAI_MAX_TOKENS': int(os.environ.get('OPENAI_MAX_TOKENS', '4000')),
    'OPENAI_TEMPERATURE': float(os.environ.get('OPENAI_TEMPERATURE', '0.1')),
}

# Server Configuration
SERVER_CONFIG = {
    'HOST': os.environ.get('SERVER_HOST', '0.0.0.0'),
    'PORT': int(os.environ.get('SERVER_PORT', '5000')),
    'DEBUG': os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
}

# GitHub/GitLab Configuration
VCS_CONFIG = {
    'GITHUB_TOKEN': os.environ.get('GITHUB_TOKEN', ''),
    'GITLAB_TOKEN': os.environ.get('GITLAB_TOKEN', ''),
    'WEBHOOK_SECRET': os.environ.get('WEBHOOK_SECRET', '')
}

def get_config() -> Dict[str, Any]:
    """Get all configuration settings as a single dictionary"""
    config = {}
    config.update(DATABASE_CONFIG)
    config.update(FLASK_CONFIG)
    config.update(LLM_CONFIG)
    config.update(SERVER_CONFIG)
    config.update(VCS_CONFIG)
    return config

def get_prompt_config() -> Dict[str, Any]:
    """Get LLM prompt configuration"""
    return {
        'model': LLM_CONFIG['OPENAI_MODEL'],
        'max_tokens': LLM_CONFIG['OPENAI_MAX_TOKENS'],
        'temperature': LLM_CONFIG['OPENAI_TEMPERATURE']
    }
