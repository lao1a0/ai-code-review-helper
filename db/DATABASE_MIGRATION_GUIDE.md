# 数据库迁移指南：Redis → PostgreSQL

## 概述

本项目已从Redis数据库迁移到PostgreSQL数据库，并添加了完整的用户认证系统和项目管理系统。

## 新功能特性

### 1. 用户系统
- 用户注册/登录功能
- 密码加密存储
- 用户会话管理
- 基于用户的数据隔离

### 2. 项目管理系统
- **GitLab项目表**: 存储GitLab项目配置
- **GitHub项目表**: 存储GitHub项目配置
- 用户-项目关联关系

### 3. 评审记录系统
- **GitLab评审表**: 记录GitLab项目的AI评审结果
- **GitHub评审表**: 记录GitHub项目的AI评审结果
- 完整的评审历史追踪

## 数据库表结构

### 用户表 (users)
| 字段名 | 类型 | 说明 |
|--------|------|------|
| id | UUID | 主键 |
| username | VARCHAR(80) | 用户名，唯一 |
| nickname | VARCHAR(100) | 昵称 |
| password_hash | VARCHAR(255) | 密码哈希 |
| created_at | TIMESTAMP | 创建时间 |
| updated_at | TIMESTAMP | 更新时间 |

### GitLab项目表 (gitlab_projects)
| 字段名 | 类型 | 说明 |
|--------|------|------|
| id | UUID | 主键 |
| user_id | UUID | 关联用户ID |
| token | VARCHAR(255) | GitLab访问令牌 |
| secret | VARCHAR(255) | Webhook密钥（可选） |
| project_id | VARCHAR(100) | GitLab项目ID |
| url | VARCHAR(500) | GitLab项目URL |
| created_at | TIMESTAMP | 创建时间 |
| updated_at | TIMESTAMP | 更新时间 |

### GitHub项目表 (github_projects)
| 字段名 | 类型 | 说明 |
|--------|------|------|
| id | UUID | 主键 |
| user_id | UUID | 关联用户ID |
| token | VARCHAR(255) | GitHub访问令牌 |
| secret | VARCHAR(255) | Webhook密钥（可选） |
| repo | VARCHAR(200) | 仓库名称 |
| owner | VARCHAR(100) | 仓库所有者 |
| created_at | TIMESTAMP | 创建时间 |
| updated_at | TIMESTAMP | 更新时间 |

### 评审记录表
GitLab评审表 (gitlab_reviews) 和 GitHub评审表 (github_reviews) 具有相同结构：

| 字段名 | 类型 | 说明 |
|--------|------|------|
| id | UUID | 主键 |
| project_id | UUID | 关联项目ID |
| ai_name | VARCHAR(100) | AI模型名称 |
| date | TIMESTAMP | 评审时间 |
| review_content | TEXT | 评审内容 |
| quality_score | FLOAT | 质量评分 |
| commit_sha | VARCHAR(40) | 提交SHA |
| pr_mr_id | VARCHAR(50) | PR/MR ID |
| branch | VARCHAR(200) | 分支名称 |
| created_at | TIMESTAMP | 创建时间 |
| updated_at | TIMESTAMP | 更新时间 |

## 快速开始

### 1. 环境准备

#### 安装PostgreSQL
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install postgresql postgresql-contrib

# macOS (使用Homebrew)
brew install postgresql
brew services start postgresql

# Windows
# 下载并安装PostgreSQL: https://www.postgresql.org/download/windows/
```

#### 创建数据库
```bash
# 连接到PostgreSQL
sudo -u postgres psql

# 创建数据库
CREATE DATABASE ai_code_review_helper;
CREATE USER postgres WITH PASSWORD 'postgres';
GRANT ALL PRIVILEGES ON DATABASE ai_code_review_helper TO postgres;
\q
```

### 2. 项目配置

#### 复制环境变量模板
```bash
cp .env.example .env
```

#### 编辑.env文件
```bash
# 数据库配置
DATABASE_URL=postgresql://username:password@localhost:5432/ai_code_review_helper

# 或者使用单独配置
DB_USER=postgres
DB_PASSWORD=your_password
DB_HOST=localhost
DB_PORT=5432
DB_NAME=ai_code_review_helper

# Flask密钥（重要：在生产环境中更改）
SECRET_KEY=your-secret-key-change-this-in-production
```

### 3. 安装依赖
```bash
pip install -r requirements.txt
```

### 4. 初始化数据库
```bash
# 方法1：使用初始化脚本
python db/init_db.py

# 方法2：自动创建（首次运行应用时）
python app.py
```

### 5. 启动应用
```bash
python app.py
```

## 使用指南

### 用户注册与登录

1. 访问 `http://localhost:8088/auth/login`
2. 使用默认管理员账号登录：
   - 用户名：admin
   - 密码：admin123
3. 或者注册新用户

### API端点

#### 认证相关
- `POST /auth/login` - 用户登录
- `POST /auth/register` - 用户注册
- `GET /auth/logout` - 用户登出
- `GET /auth/profile` - 获取用户信息

#### 项目管理（待实现）
- `GET /api/projects` - 获取用户项目列表
- `POST /api/projects/gitlab` - 创建GitLab项目
- `POST /api/projects/github` - 创建GitHub项目
- `DELETE /api/projects/{id}` - 删除项目

#### 评审记录（待实现）
- `GET /api/reviews/{project_id}` - 获取项目评审记录
- `GET /api/reviews/{project_id}/{pr_mr_id}` - 获取特定PR/MR的评审记录

## 从Redis迁移数据

由于数据结构发生了重大变化，Redis中的数据无法直接迁移到PostgreSQL。建议：

1. 记录现有的GitHub/GitLab配置
2. 在新系统中重新配置项目
3. 历史评审记录将保留在Redis中作为备份

## 开发注意事项

### 数据库操作
使用 `DatabaseService` 类进行所有数据库操作，示例：

```python
from services.database_service import DatabaseService

# 创建用户
user = DatabaseService.create_user('testuser', '测试用户', 'password123')

# 创建GitLab项目
project = DatabaseService.create_gitlab_project(
    user_id=user.id,
    token='gitlab_token',
    secret='webhook_secret',
    project_id='12345',
    url='https://gitlab.com/user/project'
)

# 创建评审记录
review = DatabaseService.create_gitlab_review(
    project_id=project.id,
    ai_name='GPT-4',
    review_content='代码质量良好...',
    quality_score=8.5,
    commit_sha='abc123def456',
    pr_mr_id='42',
    branch='main'
)
```

### 数据库迁移
使用Flask-Migrate进行数据库迁移：

```bash
# 安装Flask-Migrate
pip install Flask-Migrate

# 初始化迁移
flask db init

# 创建迁移
flask db migrate -m "描述变更"

# 应用迁移
flask db upgrade
```

## 故障排除

### 常见问题

1. **数据库连接失败**
   - 检查PostgreSQL服务是否运行
   - 验证数据库连接参数
   - 确保数据库已创建

2. **表创建失败**
   - 检查数据库权限
   - 查看应用日志获取详细错误信息

3. **登录失败**
   - 确认用户已注册
   - 检查用户名和密码

### 调试模式
```bash
# 启用SQLAlchemy调试日志
export SQLALCHEMY_ECHO=true
python app.py
```

## 安全建议

1. **生产环境配置**
   - 更改默认SECRET_KEY
   - 使用强密码
   - 配置HTTPS
   - 限制数据库访问权限

2. **密码安全**
   - 使用Werkzeug的密码哈希
   - 定期更新密码策略
   - 实施密码复杂度要求

3. **数据库安全**
   - 使用专用数据库用户
   - 限制网络访问
   - 定期备份数据
