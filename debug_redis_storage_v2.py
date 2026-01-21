#!/usr/bin/env python3
"""
调试Redis配置存储问题的脚本 - 修正版本
"""
import os
import sys
import json
import logging
from config.core_config import app_configs

# 设置日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def test_redis_direct():
    """直接测试Redis连接和存储"""
    print("🚀 开始调试Redis配置存储问题...\n")
    
    # 导入并初始化Redis
    from config.redis_config import init_redis_client, redis_client
    
    print("=== 步骤1: 初始化Redis客户端 ===")
    try:
        client = init_redis_client()
        print(f"✅ Redis客户端初始化成功: {client}")
        print(f"全局redis_client: {redis_client}")
    except Exception as e:
        print(f"❌ Redis客户端初始化失败: {e}")
        return
    
    print("\n=== 步骤2: 测试直接Redis操作 ===")
    try:
        # 测试直接设置值
        test_key = "aihelper:test_key"
        test_value = {"message": "Hello from Redis test", "timestamp": "2026-01-21"}
        
        print(f"设置测试键: {test_key}")
        result = redis_client.set(test_key, json.dumps(test_value))
        print(f"设置结果: {result}")
        
        # 测试获取值
        retrieved = redis_client.get(test_key)
        if retrieved:
            parsed = json.loads(retrieved.decode('utf-8'))
            print(f"获取结果: {parsed}")
        else:
            print("❌ 无法获取测试值")
            
    except Exception as e:
        print(f"❌ 直接Redis操作失败: {e}")
    
    print("\n=== 步骤3: 测试settings_store功能 ===")
    try:
        from services.settings_store import (
            get_project_settings, 
            set_project_settings, 
            get_agent_settings, 
            set_agent_settings
        )
        
        # 测试项目设置
        print("测试项目设置存储...")
        test_project_key = "debug_project_456"
        test_project_config = {
            "name": "调试项目",
            "settings": {"auto_review": True, "language": "python"}
        }
        
        print(f"设置项目配置: {test_project_key}")
        set_result = set_project_settings(test_project_key, test_project_config)
        print(f"设置结果: {set_result}")
        
        # 检查Redis中是否真的有数据
        redis_key = "aihelperproject_settings"
        raw_data = redis_client.hget(redis_key, test_project_key)
        if raw_data:
            parsed = json.loads(raw_data.decode('utf-8'))
            print(f"✅ Redis中找到项目配置: {parsed}")
        else:
            print("❌ Redis中没有找到项目配置")
        
        # 测试代理设置
        print("\n测试代理设置存储...")
        test_agent_config = {"model": "gpt-4", "temperature": 0.5}
        set_agent_settings(test_agent_config)
        
        agent_redis_key = "aihelperagent_settings"
        agent_raw = redis_client.get(agent_redis_key)
        if agent_raw:
            agent_parsed = json.loads(agent_raw.decode('utf-8'))
            print(f"✅ Redis中找到代理配置: {agent_parsed}")
        else:
            print("❌ Redis中没有找到代理配置")
            
    except Exception as e:
        print(f"❌ settings_store测试失败: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n=== 步骤4: 检查所有Redis键 ===")
    try:
        keys = []
        cursor = 0
        while True:
            cursor, batch_keys = redis_client.scan(cursor=cursor, match="aihelper*", count=100)
            keys.extend([key.decode('utf-8') for key in batch_keys])
            if cursor == 0:
                break
        
        print(f"找到 {len(keys)} 个匹配的键:")
        for key in sorted(keys):
            key_type = redis_client.type(key).decode('utf-8')
            print(f"  {key} ({key_type})")
            
    except Exception as e:
        print(f"❌ 检查Redis键失败: {e}")
    
    print("\n✅ 调试完成")

if __name__ == "__main__":
    test_redis_direct()
