# 数据库说明文档

## 概述

PostgreSQL数据库用于记录系统的相关信息。

## 数据库表结构

### 用户表 (users)

用于记录登录系统的用户身份

| 字段名 | 类型 | 说明 |
|--------|------|------|
| id | UUID | 主键 |
| username | VARCHAR(80) | 用户名，唯一 |
| nickname | VARCHAR(100) | 昵称 |
| password_hash | VARCHAR(255) | 密码哈希 |
| llm_type | VARCHAR(255) | 大模型的类型 |
| llm_token | VARCHAR(255) | 大模型的key |
| llm_url | VARCHAR(255) | 大模型连接的地址 |
| gitlab_token | VARCHAR(255) | Gitlab的token（可以为空） |
| github_token | VARCHAR(255) | Github的token（可以为空） |
| created_at | TIMESTAMP | 创建时间 |
| updated_at | TIMESTAMP | 更新时间 |

### GitLab项目表 (gitlab_projects)

用于记录每一个用户设置的gitlab项目信息

| 字段名 | 类型 | 说明 |
|--------|------|------|
| id | UUID | 主键 |
| user_id | UUID | 关联users表中的用户ID |
| token | VARCHAR(255) | GitLab访问令牌 |
| secret | VARCHAR(255) | Webhook密钥（可选） |
| project_id | VARCHAR(100) | GitLab项目ID |
| url | VARCHAR(500) | GitLab项目URL |
| created_at | TIMESTAMP | 创建时间 |
| updated_at | TIMESTAMP | 更新时间 |

### GitHub项目表 (github_projects)

用于记录每一个用户设置的github项目信息

| 字段名 | 类型 | 说明 |
|--------|------|------|
| id | UUID | 主键 |
| user_id | UUID | 关联users表中的用户ID |
| token | VARCHAR(255) | GitHub访问令牌 |
| secret | VARCHAR(255) | Webhook密钥（可选） |
| repo | VARCHAR(200) | 仓库名称 |
| owner | VARCHAR(100) | 仓库所有者 |
| created_at | TIMESTAMP | 创建时间 |
| updated_at | TIMESTAMP | 更新时间 |

### Github评审记录表(github_reviews)
Gitub评审表 (github_reviews)，用于记录这个项目的评审信息

| 字段名 | 类型 | 说明 |
|--------|------|------|
| id | UUID | 主键 |
| project_id | UUID | 关联github_projects表中的项目ID |
| ai_name | VARCHAR(100) | AI模型名称 |
| date | TIMESTAMP | 评审时间 |
| review_content | TEXT | 评审内容 |
| quality_score | FLOAT | 质量评分 |
| commit_sha | VARCHAR(40) | 提交SHA |
| pr_mr_id | VARCHAR(50) | PR/MR ID |
| branch | VARCHAR(200) | 分支名称 |
| created_at | TIMESTAMP | 创建时间 |
| updated_at | TIMESTAMP | 更新时间 |

### Gitlab评审记录表(gitlab_reviews)

Gitlab评审表 (github_reviews)，用于记录这个项目的评审信息

| 字段名         | 类型         | 说明                                |
| -------------- | ------------ | ----------------------------------- |
| id             | UUID         | 主键                                |
| project_id     | UUID         | 关联gitlab_projects项目表中的项目ID |
| ai_name        | VARCHAR(100) | AI模型名称                          |
| date           | TIMESTAMP    | 评审时间                            |
| review_content | TEXT         | 评审内容                            |
| quality_score  | FLOAT        | 质量评分                            |
| commit_sha     | VARCHAR(40)  | 提交SHA                             |
| pr_mr_id       | VARCHAR(50)  | PR/MR ID                            |
| branch         | VARCHAR(200) | 分支名称                            |
| created_at     | TIMESTAMP    | 创建时间                            |
| updated_at     | TIMESTAMP    | 更新时间                            |

## 快速开始（Docker 一键启动，自动初始化表结构）

1. 一键启动  

在 `docker-compose.yml` 所在目录执行：

```bash
docker compose up -d
```

2. 验证  

容器启动后，PostgreSQL 会自动执行 `/docker-entrypoint-initdb.d/01-init.sql`，5 张表连同外键、索引、UUID 扩展全部初始化完毕。  可用任意客户端连接 `localhost:5432 | db: code_review_db | user: postgres | pwd: postgres` 查看表结构。

3. 停止/清理（可选）

```bash
docker compose down -v   # 停止并删除数据卷
```

## 使用指南

### 用户注册与登录

1. 访问 `http://localhost:8088/auth/login`
2. 使用默认管理员账号登录：
   - 用户名：admin
   - 密码：admin123
3. 或者注册新用户