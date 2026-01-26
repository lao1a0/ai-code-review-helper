-- 1. 连到已自动创建的数据库（docker 会帮我们建 aihelper，所以这句也省掉）
\c aihelper;

-- 2. 启用 uuid 生成函数
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 3. 用户表
CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username      VARCHAR(80)  NOT NULL UNIQUE,
    nickname      VARCHAR(100),
    password_hash VARCHAR(255) NOT NULL,
    llm_type      VARCHAR(255),
    llm_token     VARCHAR(255),
    llm_url       VARCHAR(255),
    gitlab_token  VARCHAR(255),
    github_token  VARCHAR(255),
    created_at    TIMESTAMP DEFAULT NOW(),
    updated_at    TIMESTAMP DEFAULT NOW()
);

-- 4. GitLab 项目表
CREATE TABLE IF NOT EXISTS gitlab_projects (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
    token      VARCHAR(255) NOT NULL,
    secret     VARCHAR(255),
    project_id VARCHAR(100) NOT NULL,
    url        VARCHAR(500) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- 5. GitHub 项目表
CREATE TABLE IF NOT EXISTS github_projects (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
    token      VARCHAR(255) NOT NULL,
    secret     VARCHAR(255),
    repo       VARCHAR(200) NOT NULL,
    owner      VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- 6. GitHub 评审记录表
CREATE TABLE IF NOT EXISTS github_reviews (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id     UUID REFERENCES github_projects(id) ON DELETE CASCADE,
    ai_name        VARCHAR(100),
    date           TIMESTAMP DEFAULT NOW(),
    review_content TEXT,
    quality_score  FLOAT,
    commit_sha     VARCHAR(40),
    pr_mr_id       VARCHAR(50),
    branch         VARCHAR(200),
    created_at     TIMESTAMP DEFAULT NOW(),
    updated_at     TIMESTAMP DEFAULT NOW()
);

-- 7. GitLab 评审记录表
CREATE TABLE IF NOT EXISTS gitlab_reviews (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id     UUID REFERENCES gitlab_projects(id) ON DELETE CASCADE,
    ai_name        VARCHAR(100),
    date           TIMESTAMP DEFAULT NOW(),
    review_content TEXT,
    quality_score  FLOAT,
    commit_sha     VARCHAR(40),
    pr_mr_id       VARCHAR(50),
    branch         VARCHAR(200),
    created_at     TIMESTAMP DEFAULT NOW(),
    updated_at     TIMESTAMP DEFAULT NOW()
);