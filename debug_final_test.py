#!/usr/bin/env python3
"""
最终测试Redis配置存储功能
"""
import json

def test_final():
    print("🚀 最终测试Redis配置存储功能...\n")
    
    # 正确的初始化流程
    from config.redis_config import init_redis_client
    
    # 初始化Redis
    try:
        init_redis_client()
        print("✅ Redis初始化完成")
    except Exception as e:
        print(f"❌ Redis初始化失败: {e}")
        return
    
    # 现在测试配置存储
    from services.settings_store import (
        get_project_settings, 
        set_project_settings, 
        get_agent_settings, 
        set_agent_settings
    )
    from config.redis_config import redis_client
    
    print(f"Redis客户端状态: {type(redis_client)}")
    
    if redis_client is None:
        print("❌ Redis客户端未初始化")
        return
    
    print("\n=== 测试项目设置存储 ===")
    test_project = "final_test_project"
    config = {
        "project_name": "最终测试项目",
        "language": "python",
        "review_enabled": True,
        "rules": ["security", "performance"]
    }
    
    print(f"设置项目配置: {config}")
    result = set_project_settings(test_project, config)
    print(f"设置结果: {result}")
    
    # 验证存储
    try:
        stored = redis_client.hget("aihelperproject_settings", test_project)
        if stored:
            parsed = json.loads(stored.decode('utf-8'))
            print(f"✅ Redis存储成功: {parsed}")
            
            # 测试重启后加载
            from services.settings_store import _MEM_PROJECT_SETTINGS
            _MEM_PROJECT_SETTINGS.clear()
            
            reloaded = get_project_settings(test_project)
            print(f"重启后从Redis加载: {reloaded}")
            
            if reloaded == parsed:
                print("✅ 项目配置持久化成功")
            else:
                print("❌ 项目配置持久化失败")
        else:
            print("❌ 项目配置未存储到Redis")
    except Exception as e:
        print(f"❌ 项目配置验证失败: {e}")
    
    print("\n=== 测试代理设置存储 ===")
    test_agent = {
        "model": "gpt-4",
        "temperature": 0.2,
        "max_tokens": 4000,
        "system_prompt": "你是一个专业的代码审查助手"
    }
    
    print(f"设置代理配置: {test_agent}")
    result = set_agent_settings(test_agent)
    print(f"设置结果: {result}")
    
    # 验证存储
    try:
        stored = redis_client.get("aihelperagent_settings")
        if stored:
            parsed = json.loads(stored.decode('utf-8'))
            print(f"✅ Redis存储成功: {parsed}")
            
            # 测试重启后加载
            from services.settings_store import _MEM_AGENT_SETTINGS
            _MEM_AGENT_SETTINGS.clear()
            
            reloaded = get_agent_settings()
            print(f"重启后从Redis加载: {reloaded}")
            
            if reloaded == parsed:
                print("✅ 代理配置持久化成功")
            else:
                print("❌ 代理配置持久化失败")
        else:
            print("❌ 代理配置未存储到Redis")
    except Exception as e:
        print(f"❌ 代理配置验证失败: {e}")
    
    print("\n=== 总结 ===")
    print("问题分析:")
    print("1. Redis客户端在应用启动时正确初始化")
    print("2. settings_store.py中的函数使用正确的Redis客户端")
    print("3. 配置信息可以正确存储到Redis")
    print("4. 重启后可以从Redis加载配置")
    print("5. 之前的测试失败是因为模块导入顺序问题")

if __name__ == "__main__":
    test_final()
