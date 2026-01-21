#!/usr/bin/env python3
"""
简化版Redis配置存储调试脚本
"""
import json
import logging

# 设置日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def main():
    print("🚀 开始调试Redis配置存储问题...\n")
    
    # 初始化Redis
    from config.redis_config import init_redis_client, redis_client
    from services.settings_store import (
        get_project_settings, 
        set_project_settings, 
        get_agent_settings, 
        set_agent_settings
    )
    
    print("=== 初始化Redis ===")
    try:
        init_redis_client()
        print(f"✅ Redis初始化成功: {type(redis_client)}")
        
        # 测试连接
        ping = redis_client.ping()
        print(f"✅ Redis ping: {ping}")
    except Exception as e:
        print(f"❌ Redis初始化失败: {e}")
        return
    
    print("\n=== 测试项目设置 ===")
    test_key = "test_project"
    test_config = {"name": "测试项目", "language": "python"}
    
    print(f"设置配置: {test_config}")
    result = set_project_settings(test_key, test_config)
    print(f"设置结果: {result}")
    
    # 验证Redis存储
    try:
        from config.redis_config import redis_client
        stored = redis_client.hget("aihelperproject_settings", test_key)
        if stored:
            parsed = json.loads(stored.decode('utf-8'))
            print(f"✅ Redis存储成功: {parsed}")
        else:
            print("❌ Redis中没有存储数据")
    except Exception as e:
        print(f"❌ 验证失败: {e}")
    
    print("\n=== 测试代理设置 ===")
    test_agent = {"model": "gpt-4", "temp": 0.7}
    print(f"设置代理: {test_agent}")
    set_agent_settings(test_agent)
    
    # 验证代理设置
    try:
        stored = redis_client.get("aihelperagent_settings")
        if stored:
            parsed = json.loads(stored.decode('utf-8'))
            print(f"✅ 代理设置存储成功: {parsed}")
        else:
            print("❌ 代理设置未存储")
    except Exception as e:
        print(f"❌ 代理验证失败: {e}")
    
    print("\n=== 检查所有键 ===")
    try:
        keys = redis_client.keys("aihelper*")
        for key in keys:
            key_str = key.decode('utf-8')
            print(f"  {key_str}")
    except Exception as e:
        print(f"❌ 检查键失败: {e}")

if __name__ == "__main__":
    main()
