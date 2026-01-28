# 数据库说明文档

## 概述

PostgreSQL数据库用于记录审计的结果的相关信息。

## 数据库表结构

### 评审记录表(reviews)

评审表 (reviews)，用于记录项目的评审信息

| 字段名            | 类型 | 说明                  |
|----------------|------|---------------------|
| id             | UUID | 主键                  |
| projectType    | VARCHAR(100) | 项目类型（Github/Gitlab） |
| project        | VARCHAR(100) | 项目的repo             |
| date           | TIMESTAMP | 评审时间                |
| review_content | TEXT | 评审内容                |
| quality_score  | FLOAT | 质量评分                |
| commit_sha     | VARCHAR(40) | 提交SHA               |
| pr_mr_id       | VARCHAR(50) | PR/MR ID            |
| branch         | VARCHAR(200) | 分支名称                |
| created_at     | TIMESTAMP | 创建时间                |
| updated_at     | TIMESTAMP | 更新时间                |

## 快速开始（Docker 一键启动，自动初始化表结构）

1. 一键启动  

在 `docker-compose.yml` 所在目录执行：

```bash
docker compose up -d
```

2. 验证  

容器启动后，PostgreSQL 会自动执行 `/docker-entrypoint-initdb.d/01-init.sql`。

3. 停止/清理（可选）

```bash
docker compose down -v   # 停止并删除数据卷
```