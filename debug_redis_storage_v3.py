#!/usr/bin/env python3
"""
调试Redis配置存储问题的脚本 - 模拟实际应用启动流程
"""
import os
import sys
import json
import logging

# 设置日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def test_redis_with_proper_initialization():
    """模拟实际应用启动流程测试Redis"""
    print("🚀 开始调试Redis配置存储问题 - 模拟实际应用启动流程...\n")
    
    # 模拟app.py的初始化流程
    print("=== 步骤1: 模拟应用启动初始化 ===")
    
    # 导入并初始化Redis，类似app.py
    from config.redis_config import init_redis_client, load_configs_from_redis, redis_client
    from services.settings_store import (
        get_project_settings, 
        set_project_settings, 
        get_agent_settings, 
        set_agent_settings
    )
    
    try:
        # 模拟app.py的初始化
        redis_result = init_redis_client()
        if redis_result is not None:
            load_configs_from_redis()
            print(f"✅ Redis客户端初始化成功: {redis_client}")
        else:
            print("❌ Redis客户端初始化失败")
            return
    except Exception as e:
        print(f"❌ Redis初始化失败: {e}")
        return
    
    print("\n=== 步骤2: 测试项目设置存储到Redis ===")
    
    test_project_key = "test_project_789"
    test_settings = {
        "project_name": "测试项目存储",
        "language": "python",
        "review_rules": ["security", "performance", "style"],
        "created_at": "2026-01-21T18:40:00"
    }
    
    print(f"1. 设置项目配置: {test_project_key}")
    print(f"配置内容: {json.dumps(test_settings, indent=2, ensure_ascii=False)}")
    
    # 设置配置
    set_result = set_project_settings(test_project_key, test_settings)
    print(f"设置结果: {set_result}")
    
    print(f"\n2. 从Redis验证存储:")
    try:
        # 直接从Redis获取验证
        from config.redis_config import redis_client
        redis_key = "aihelperproject_settings"
        raw_data = redis_client.hget(redis_key, test_project_key)
        if raw_data:
            redis_settings = json.loads(raw_data.decode('utf-8'))
            print(f"✅ Redis中找到项目配置: {json.dumps(redis_settings, indent=2, ensure_ascii=False)}")
            
            # 验证内存和Redis是否一致
            mem_settings = get_project_settings(test_project_key)
            if mem_settings == redis_settings:
                print("✅ 内存和Redis配置一致")
            else:
                print("❌ 内存和Redis配置不一致")
                print(f"内存: {mem_settings}")
                print(f"Redis: {redis_settings}")
        else:
            print("❌ Redis中没有找到项目配置")
    except Exception as e:
        print(f"❌ 验证Redis存储失败: {e}")
    
    print(f"\n3. 测试重启后从Redis加载:")
    try:
        # 模拟重启，清除内存
        from services.settings_store import _MEM_PROJECT_SETTINGS
        _MEM_PROJECT_SETTINGS.clear()
        
        # 重新获取（应该能从Redis加载）
        reloaded_settings = get_project_settings(test_project_key)
        if reloaded_settings:
            print(f"✅ 重启后成功从Redis加载配置: {json.dumps(reloaded_settings, indent=2, ensure_ascii=False)}")
        else:
            print("❌ 重启后无法从Redis加载配置")
    except Exception as e:
        print(f"❌ 重启测试失败: {e}")
    
    print("\n=== 步骤3: 测试代理设置存储到Redis ===")
    
    test_agent_config = {
        "model": "gpt-4-turbo",
        "temperature": 0.3,
        "max_tokens": 4000,
        "system_prompt": "你是一个代码审查助手"
    }
    
    print(f"1. 设置代理配置:")
    print(f"配置内容: {json.dumps(test_agent_config, indent=2, ensure_ascii=False)}")
    
    set_agent_settings(test_agent_config)
    
    print(f"\n2. 从Redis验证存储:")
    try:
        agent_redis_key = "aihelperagent_settings"
        agent_raw = redis_client.get(agent_redis_key)
        if agent_raw:
            agent_parsed = json.loads(agent_raw.decode('utf-8'))
            print(f"✅ Redis中找到代理配置: {json.dumps(agent_parsed, indent=2, ensure_ascii=False)}")
        else:
            print("❌ Redis中没有找到代理配置")
    except Exception as e:
        print(f"❌ 验证代理配置失败: {e}")
    
    print("\n=== 步骤4: 检查所有Redis中的配置键 ===")
    try:
        keys = []
        cursor = 0
        while True:
            cursor, batch_keys = redis_client.scan(cursor=cursor, match="aihelper*", count=100)
            keys.extend([key.decode('utf-8') for key in batch_keys])
            if cursor == 0:
                break
        
        print(f"找到 {len(keys)} 个匹配的键:")
        config_keys = [k for k in keys if 'settings' in k or 'config' in k]
        for key in sorted(config_keys):
            key_type = redis_client.type(key).decode('utf-8')
            print(f"  🔑 {key} ({key_type})")
            
            if key_type == 'hash':
                fields = redis_client.hgetall(key)
                for field, value in fields.items():
                    field_str = field.decode('utf-8')
                    try:
                        value_parsed = json.loads(value.decode('utf-8'))
                        print(f"    {field_str}: {json.dumps(value_parsed, indent=2, ensure_ascii=False)}")
                    except:
                        print(f"    {field_str}: {value.decode('utf-8')[:100]}...")
            elif key_type == 'string':
                value = redis_client.get(key)
                if value:
                    try:
                        value_parsed = json.loads(value.decode('utf-8'))
                        print(f"    值: {json.dumps(value_parsed, indent=2, ensure_ascii=False)}")
                    except:
                        print(f"    值: {value.decode('utf-8')[:100]}...")
                        
    except Exception as e:
        print(f"❌ 检查Redis键失败: {e}")
    
    print("\n✅ 调试完成 - 模拟实际应用启动流程")

if __name__ == "__main__":
    test_redis_with_proper_initialization()
