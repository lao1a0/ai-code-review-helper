#!/usr/bin/env python3
"""
调试Redis配置存储问题的脚本 - 详细错误分析
"""
import os
import sys
import json
import logging
import traceback

# 设置日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def debug_settings_store():
    """详细调试settings_store.py的问题"""
    print("🚀 开始详细调试Redis配置存储问题...\n")
    
    # 导入并初始化Redis
    from config.redis_config import init_redis_client, redis_client
    from services.settings_store import (
        get_project_settings, 
        set_project_settings, 
        get_agent_settings, 
        set_agent_settings,
        REDIS_AGENT_SETTINGS_KEY,
        REDIS_PROJECT_SETTINGS_KEY
    )
    
    print("=== 步骤1: 初始化Redis客户端 ===")
    try:
        client = init_redis_client()
        print(f"✅ Redis客户端初始化成功")
        print(f"redis_client类型: {type(redis_client)}")
        print(f"redis_client值: {redis_client}")
    except Exception as e:
        print(f"❌ Redis客户端初始化失败: {e}")
        return
    
    print("\n=== 步骤2: 检查Redis连接状态 ===")
    try:
        # 测试Redis连接
        ping_result = redis_client.ping()
        print(f"✅ Redis ping结果: {ping_result}")
        
        # 测试基本操作
        test_result = redis_client.set("test:connection", "ok")
        print(f"✅ Redis set测试结果: {test_result}")
        
        get_result = redis_client.get("test:connection")
        print(f"✅ Redis get测试结果: {get_result}")
        
    except Exception as e:
        print(f"❌ Redis连接测试失败: {e}")
        return
    
    print("\n=== 步骤3: 详细调试项目设置存储 ===")
    
    test_project_key = "debug_detailed_001"
    test_settings = {
        "project_name": "详细调试项目",
        "language": "python",
        "debug": True
    }
    
    print(f"测试项目键: {test_project_key}")
    print(f"测试配置: {json.dumps(test_settings, indent=2, ensure_ascii=False)}")
    
    # 手动测试Redis操作
    print("\n3.1 手动测试Redis hash操作:")
    try:
        redis_key = REDIS_PROJECT_SETTINGS_KEY
        print(f"Redis键: {redis_key}")
        
        # 手动设置
        manual_data = json.dumps(test_settings, ensure_ascii=False)
        print(f"序列化数据: {manual_data}")
        
        hset_result = redis_client.hset(redis_key, test_project_key, manual_data)
        print(f"✅ 手动hset结果: {hset_result}")
        
        # 手动获取
        manual_get = redis_client.hget(redis_key, test_project_key)
        if manual_get:
            manual_parsed = json.loads(manual_get.decode('utf-8'))
            print(f"✅ 手动hget结果: {json.dumps(manual_parsed, indent=2, ensure_ascii=False)}")
        else:
            print("❌ 手动hget失败")
            
    except Exception as e:
        print(f"❌ 手动Redis操作失败: {e}")
        traceback.print_exc()
    
    print("\n3.2 测试set_project_settings函数:")
    try:
        # 清除之前的测试数据
        redis_client.hdel(REDIS_PROJECT_SETTINGS_KEY, test_project_key)
        
        # 使用函数设置
        print("调用set_project_settings...")
        result = set_project_settings(test_project_key, test_settings)
        print(f"函数返回结果: {result}")
        
        # 验证存储
        verify_data = redis_client.hget(REDIS_PROJECT_SETTINGS_KEY, test_project_key)
        if verify_data:
            verify_parsed = json.loads(verify_data.decode('utf-8'))
            print(f"✅ 验证存储成功: {json.dumps(verify_parsed, indent=2, ensure_ascii=False)}")
        else:
            print("❌ 验证存储失败 - 数据未存储到Redis")
            
    except Exception as e:
        print(f"❌ set_project_settings失败: {e}")
        traceback.print_exc()
    
    print("\n=== 步骤4: 详细调试代理设置存储 ===")
    
    test_agent_config = {"model": "gpt-4", "debug": True}
    
    print(f"测试代理配置: {json.dumps(test_agent_config, indent=2, ensure_ascii=False)}")
    
    print("\n4.1 手动测试Redis string操作:")
    try:
        redis_key = REDIS_AGENT_SETTINGS_KEY
        print(f"Redis键: {redis_key}")
        
        manual_data = json.dumps(test_agent_config, ensure_ascii=False)
        set_result = redis_client.set(redis_key, manual_data)
        print(f"✅ 手动set结果: {set_result}")
        
        manual_get = redis_client.get(redis_key)
        if manual_get:
            manual_parsed = json.loads(manual_get.decode('utf-8'))
            print(f"✅ 手动get结果: {json.dumps(manual_parsed, indent=2, ensure_ascii=False)}")
        else:
            print("❌ 手动get失败")
            
    except Exception as e:
        print(f"❌ 手动Redis操作失败: {e}")
        traceback.print_exc()
    
    print("\n4.2 测试set_agent_settings函数:")
    try:
        # 清除之前的测试数据
        redis_client.delete(REDIS_AGENT_SETTINGS_KEY)
        
        print("调用set_agent_settings...")
        result = set_agent_settings(test_agent_config)
        print(f"函数返回结果: {result}")
        
        # 验证存储
        verify_data = redis_client.get(REDIS_AGENT_SETTINGS_KEY)
        if verify_data:
            verify_parsed = json.loads(verify_data.decode('utf-8'))
            print(f"✅ 验证存储成功: {json.dumps(verify_parsed, indent=2, ensure_ascii=False)}")
        else:
            print("❌ 验证存储失败 - 数据未存储到Redis")
            
    except Exception as e:
        print(f"❌ set_agent_settings失败: {e}")
        traceback.print_exc()
    
    print("\n=== 步骤5: 检查settings_store.py的异常处理 ===")
    try:
        # 检查settings_store.py中的异常处理
        print("检查settings_store.py的异常处理逻辑...")
        
        # 测试当redis_client为None时的情况
        print(f"当前redis_client: {redis_client is not None}")
        
        # 故意制造一个错误来测试异常处理
        original_client = redis_client
        try:
            # 临时设置redis_client为None来测试异常处理
            from services import settings_store
            settings_store.redis_client = None
            
            test_error_config = {"test": "error_handling"}
            result = set_project_settings("error_test", test_error_config)
            print(f"异常处理测试结果: {result}")
            
        finally:
            # 恢复redis_client
            settings_store.redis_client = original_client
            
    except Exception as e:
        print(f"❌ 异常处理测试失败: {e}")
        traceback.print_exc()
    
    print("\n=== 步骤6: 最终验证所有存储的键 ===")
    try:
        keys = []
        cursor = 0
        while True:
            cursor, batch_keys = redis_client.scan(cursor=cursor, match="aihelper*", count=100)
            keys.extend([key.decode('utf-8')
