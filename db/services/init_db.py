#!/usr/bin/env python3
"""
数据库初始化脚本
用于创建数据库表和初始数据
"""

import os
import sys
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app import app
from db.models import db
from db.models.user import User

def init_database():
    """初始化数据库"""
    with app.app_context():
        try:
            # 创建所有表
            db.create_all()
            print("✅ 数据库表创建成功")
            
            # 检查是否已存在管理员用户
            admin_user = User.query.filter_by(username='admin').first()
            if not admin_user:
                # 创建默认管理员用户
                admin = User(
                    username='admin',
                    nickname='管理员'
                )
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()
                print("✅ 默认管理员用户创建成功")
                print("   用户名: admin")
                print("   密码: admin123")
            else:
                print("ℹ️  管理员用户已存在")
                
        except Exception as e:
            print(f"❌ 数据库初始化失败: {e}")
            return False
            
    return True

if __name__ == '__main__':
    print("开始初始化数据库...")
    if init_database():
        print("🎉 数据库初始化完成！")
    else:
        print("💥 数据库初始化失败！")
        sys.exit(1)
