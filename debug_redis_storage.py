#!/usr/bin/env python3
"""
调试Redis配置存储问题的脚本
"""
import os
import sys
import json
import logging
from config.redis_config import init_redis_client, redis_client
from services.settings_store import (
    get_project_settings, 
    set_project_settings, 
    get_agent_settings, 
    set_agent_settings
)

# 设置日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def test_redis_connection():
    """测试Redis连接"""
    print("=== 测试Redis连接 ===")
    try:
        client = init_redis_client()
        print(f"✅ Redis连接成功: {client}")
        return True
    except Exception as e:
        print(f"❌ Redis连接失败: {e}")
        return False

def test_project_settings_storage():
    """测试项目设置存储"""
    print("\n=== 测试项目设置存储 ===")
    
    test_project_key = "test_project_123"
    test_settings = {
        "project_name": "测试项目",
        "language": "python",
        "review_rules": ["security", "performance"]
    }
    
    print(f"1. 设置项目配置: {test_project_key}")
    print(f"配置内容: {json.dumps(test_settings, indent=2, ensure_ascii=False)}")
    
    # 设置配置
    result = set_project_settings(test_project_key, test_settings)
    print(f"设置结果: {result}")
    
    # 从内存获取
    print(f"\n2. 从内存获取配置:")
    mem_settings = get_project_settings(test_project_key)
    print(f"内存配置: {json.dumps(mem_settings, indent=2, ensure_ascii=False)}")
    
    # 直接从Redis获取
    print(f"\n3. 直接从Redis获取配置:")
    if redis_client:
        try:
            raw_data = redis_client.hget("aihelperproject_settings", test_project_key)
            if raw_data:
                redis_settings = json.loads(raw_data.decode('utf-8'))
                print(f"Redis配置: {json.dumps(redis_settings, indent=2, ensure_ascii=False)}")
            else:
                print("❌ Redis中没有找到配置")
        except Exception as e:
            print(f"❌ 从Redis获取配置失败: {e}")
    else:
        print("❌ Redis客户端不可用")

def test_agent_settings_storage():
    """测试代理设置存储"""
    print("\n=== 测试代理设置存储 ===")
    
    test_settings = {
        "model": "gpt-4",
        "temperature": 0.7,
        "max_tokens": 2000
    }
    
    print(f"1. 设置代理配置:")
    print(f"配置内容: {json.dumps(test_settings, indent=2, ensure_ascii=False)}")
    
    # 设置配置
    result = set_agent_settings(test_settings)
    print(f"设置结果: {result}")
    
    # 从内存获取
    print(f"\n2. 从内存获取配置:")
    mem_settings = get_agent_settings()
    print(f"内存配置: {json.dumps(mem_settings, indent=2, ensure_ascii=False)}")
    
    # 直接从Redis获取
    print(f"\n3. 直接从Redis获取配置:")
    if redis_client:
        try:
            raw_data = redis_client.get("aihelperagent_settings")
            if raw_data:
                redis_settings = json.loads(raw_data.decode('utf-8'))
                print(f"Redis配置: {json.dumps(redis_settings, indent=2, ensure_ascii=False)}")
            else:
                print("❌ Redis中没有找到配置")
        except Exception as e:
            print(f"❌ 从Redis获取配置失败: {e}")
    else:
        print("❌ Redis客户端不可用")

def check_redis_keys():
    """检查Redis中的键"""
    print("\n=== 检查Redis中的键 ===")
    if not redis_client:
        print("❌ Redis客户端不可用")
        return
    
    try:
        # 获取所有匹配的键
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
            if key_type == 'hash':
                # 获取hash的所有字段
                fields = redis_client.hgetall(key)
                print(f"\n🔑 {key} (hash):")
                for field, value in fields.items():
                    field_str = field.decode('utf-8')
                    try:
                        value_str = value.decode('utf-8')
                        # 尝试解析JSON
                        parsed = json.loads(value_str)
                        print(f"  {field_str}: {json.dumps(parsed, indent=2, ensure_ascii=False)}")
                    except:
                        print(f"  {field_str}: {value_str[:100]}...")
            elif key_type == 'string':
                value = redis_client.get(key)
                if value:
                    value_str = value.decode('utf-8')
                    try:
                        parsed = json.loads(value_str)
                        print(f"\n🔑 {key} (string): {json.dumps(parsed, indent=2, ensure_ascii=False)}")
                    except:
                        print(f"\n🔑 {key} (string): {value_str[:100]}...")
            else:
                print(f"\n🔑 {key} ({key_type})")
                
    except Exception as e:
        print(f"❌ 检查Redis键失败: {e}")

def main():
    """主函数"""
    print("🚀 开始调试Redis配置存储问题...\n")
    
    # 测试Redis连接
    if not test_redis_connection():
        print("❌ Redis连接失败，停止测试")
        return
    
    # 检查Redis键
    check_redis_keys()
    
    # 测试项目设置存储
    test_project_settings_storage()
    
    # 测试代理设置存储
    test_agent_settings_storage()
    
    # 再次检查Redis键
    print("\n=== 存储后再次检查Redis键 ===")
    check_redis_keys()
    
    print("\n✅ 调试完成")

if __name__ == "__main__":
    main()
