#!/usr/bin/env python3
"""
调试模块导入和全局变量问题
"""
import json

def test_module_import():
    print("🚀 调试模块导入和全局变量问题...\n")
    
    print("=== 测试1: 直接访问全局变量 ===")
    from config.redis_config import redis_client as direct_client
    print(f"直接导入的redis_client: {direct_client}")
    
    print("\n=== 测试2: 初始化后访问 ===")
    from config.redis_config import init_redis_client, redis_client
    
    print(f"初始化前: {redis_client}")
    init_redis_client()
    print(f"初始化后: {redis_client}")
    
    print("\n=== 测试3: 检查settings_store.py的导入 ===")
    from services.settings_store import redis_client as settings_client
    print(f"settings_store.py中的redis_client: {settings_client}")
    
    print("\n=== 测试4: 验证Redis功能 ===")
    if redis_client is not None:
        try:
            # 测试基本功能
            redis_client.set("test:global", "works")
            result = redis_client.get("test:global")
            print(f"✅ Redis功能正常: {result}")
            
            # 测试项目设置
            from services.settings_store import set_project_settings
            set_project_settings("test_key", {"test": "value"})
            
            stored = redis_client.hget("aihelperproject_settings", "test_key")
            if stored:
                parsed = json.loads(stored.decode('utf-8'))
                print(f"✅ 项目设置存储成功: {parsed}")
            else:
                print("❌ 项目设置存储失败")
                
        except Exception as e:
            print(f"❌ Redis操作失败: {e}")
    else:
        print("❌ Redis客户端未初始化")

if __name__ == "__main__":
    test_module_import()
