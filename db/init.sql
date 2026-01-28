CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS reviews (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    projectType VARCHAR(100) NOT NULL,
    project VARCHAR(100) NOT NULL,
    date TIMESTAMP NOT NULL DEFAULT NOW(),
    review_content TEXT NOT NULL,
    quality_score FLOAT,
    commit_sha VARCHAR(40) NOT NULL,
    pr_mr_id VARCHAR(50) NOT NULL,
    branch VARCHAR(200),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
