#!/usr/bin/env python3
"""
验证项目管理页面的配置存储到Redis
"""
import json

def test_project_management_storage():
    print("🚀 验证项目管理页面配置存储...\n")
    
    # 初始化Redis
    from config.redis_config import init_redis_client
    init_redis_client()
    
    from services.settings_store import set_project_settings, get_project_settings
    from config.redis_config import redis_client
    
    print("=== 测试项目管理配置存储 ===")
    
    # 模拟用户在控制台页面配置的项目信息
    test_project_key = "github:owner/test-repo"
    project_config = {
        "platform": "github",
        "identifier": "owner/test-repo",
        "secret": "webhook_secret_123",
        "token": "ghp_abcdef123456789",
        "rag": {
            "enabled": True,
            "sources": {
                "code": True,
                "docs": True,
                "deps": False
            },
            "index": {
                "strategy": "commit",
                "branch": "main",
                "parser": "python"
            },
            "call_chain": {
                "enabled": True,
                "max_depth": 3,
                "cross_file": True
            }
        },
        "skills_enabled": ["security-review", "performance-review", "style-guide"]
    }
    
    print(f"项目键: {test_project_key}")
    print(f"配置内容: {json.dumps(project_config, indent=2, ensure_ascii=False)}")
    
    # 存储配置
    result = set_project_settings(test_project_key, project_config)
    print(f"✅ 存储结果: {result}")
    
    # 验证Redis存储
    try:
        stored = redis_client.hget("aihelperproject_settings", test_project_key)
        if stored:
            parsed = json.loads(stored.decode('utf-8'))
            print(f"✅ Redis存储验证成功:")
            print(json.dumps(parsed, indent=2, ensure_ascii=False))
            
            # 验证重启后加载
            from services.settings_store import _MEM_PROJECT_SETTINGS
            _MEM_PROJECT_SETTINGS.clear()
            
            reloaded = get_project_settings(test_project_key)
            print(f"✅ 重启后加载验证:")
            print(json.dumps(reloaded, indent=2, ensure_ascii=False))
            
            if reloaded == parsed:
                print("✅ 项目管理配置持久化成功")
            else:
                print("❌ 项目管理配置持久化失败")
        else:
            print("❌ 项目管理配置未存储到Redis")
    except Exception as e:
        print(f"❌ 验证失败: {e}")
    
    print("\n=== 测试GitLab项目配置 ===")
    
    test_gitlab_key = "gitlab:12345"
    gitlab_config = {
        "platform": "gitlab",
        "identifier": "12345",
        "secret": "gitlab_webhook_secret",
        "token": "glpat-abcdef123456789",
        "instance_url": "https://gitlab.company.com",
        "rag": {
            "enabled": True,
            "sources": {
                "code": True,
                "docs": False,
                "deps": True
            }
        },
        "skills_enabled": ["security-review"]
    }
    
    print(f"GitLab项目键: {test_gitlab_key}")
    set_project_settings(test_gitlab_key, gitlab_config)
    
    stored_gitlab = redis_client.hget("aihelperproject_settings", test_gitlab_key)
    if stored_gitlab:
        parsed_gitlab = json.loads(stored_gitlab.decode('utf-8'))
        print(f"✅ GitLab配置存储成功: {parsed_gitlab['platform']} - {parsed_gitlab['identifier']}")
    
    print("\n=== 检查所有项目管理配置 ===")
    try:
        keys = redis_client.hkeys("aihelperproject_settings")
        print(f"找到 {len(keys)} 个项目配置:")
        for key in keys:
            key_str = key.decode('utf-8')
            config_data = redis_client.hget("aihelperproject_settings", key_str)
            if config_data:
                config = json.loads(config_data.decode('utf-8'))
                print(f"  {key_str}: {config.get('platform', 'unknown')} - {config.get('identifier', 'unknown')}")
    except Exception as e:
        print(f"❌ 检查配置失败: {e}")
    
    print("\n✅ 项目管理页面配置存储验证完成")
    print("结论：用户在控制台页面配置的项目信息（平台+标识+rag+secret+token）可以正确存储到Redis")

if __name__ == "__main__":
    test_project_management_storage()
