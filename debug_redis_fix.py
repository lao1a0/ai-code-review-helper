#!/usr/bin/env python3
"""
验证Redis配置存储问题的修复
"""
import json
import logging

# 设置日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def main():
    print("🚀 开始验证Redis配置存储问题修复...\n")
    
    # 直接导入和使用Redis客户端
    from config.redis_config import init_redis_client, redis_client
    from services.settings_store import (
        get_project_settings, 
        set_project_settings, 
        get_agent_settings, 
        set_agent_settings
    )
    
    print("=== 直接初始化Redis ===")
    try:
        # 直接调用init_redis_client，不检查返回值
        init_redis_client()
        
        # 检查全局变量
        print(f"全局redis_client: {type(redis_client)}")
        
        if redis_client is None:
            print("❌ 全局redis_client仍然是None")
            return
            
        # 测试连接
        ping = redis_client.ping()
        print(f"✅ Redis连接成功: {ping}")
        
    except Exception as e:
        print(f"❌ Redis初始化失败: {e}")
        return
    
    print("\n=== 测试项目设置存储 ===")
    test_key = "fix_test_project"
    test_config = {"name": "修复测试项目", "language": "python", "rules": ["security"]}
    
    print(f"设置配置: {test_config}")
    result = set_project_settings(test_key, test_config)
    print(f"设置结果: {result}")
    
    # 验证Redis存储
    try:
        stored = redis_client.hget("aihelperproject_settings", test_key)
        if stored:
            parsed = json.loads(stored.decode('utf-8'))
            print(f"✅ Redis存储成功: {parsed}")
            
            # 测试重启后加载
            from services.settings_store import _MEM_PROJECT_SETTINGS
            _MEM_PROJECT_SETTINGS.clear()  # 模拟重启
            
            reloaded = get_project_settings(test_key)
            print(f"重启后加载: {reloaded}")
            
            if reloaded == parsed:
                print("✅ 重启后配置正确加载")
            else:
                print("❌ 重启后配置加载失败")
        else:
            print("❌ Redis中没有存储数据")
    except Exception as e:
        print(f"❌ 验证失败: {e}")
    
    print("\n=== 测试代理设置存储 ===")
    test_agent = {"model": "gpt-4-turbo", "temperature": 0.3}
    print(f"设置代理: {test_agent}")
    set_agent_settings(test_agent)
    
    # 验证代理设置
    try:
        stored = redis_client.get("aihelperagent_settings")
        if stored:
            parsed = json.loads(stored.decode('utf-8'))
            print(f"✅ 代理设置存储成功: {parsed}")
            
            # 测试重启后加载
            from services.settings_store import _MEM_AGENT_SETTINGS
            _MEM_AGENT_SETTINGS.clear()  # 模拟重启
            
            reloaded = get_agent_settings()
            print(f"重启后加载: {reloaded}")
            
            if reloaded == parsed:
                print("✅ 重启后代理配置正确加载")
            else:
                print("❌ 重启后代理配置加载失败")
        else:
            print("❌ 代理设置未存储")
    except Exception as e:
        print(f"❌ 代理验证失败: {e}")
    
    print("\n=== 检查所有Redis键 ===")
    try:
        keys = redis_client.keys("aihelper*")
        print(f"找到 {len(keys)} 个键:")
        for key in keys:
            key_str = key.decode('utf-8')
            print(f"  {key_str}")
    except Exception as e:
        print(f"❌ 检查键失败: {e}")

if __name__ == "__main__":
    main()
