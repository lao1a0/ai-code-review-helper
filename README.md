# AI Code Review Helper | 智能代码审查助手  

[English](https://www.readme-i18n.com/dingyufei615/ai-code-review-helper?lang=en) | [中文](https://www.readme-i18n.com/dingyufei615/ai-code-review-helper?lang=zh) | [日本語](https://www.readme-i18n.com/dingyufei615/ai-code-review-helper?lang=ja) | [Deutsch](https://www.readme-i18n.com/dingyufei615/ai-code-review-helper?lang=de) | [Español](https://www.readme-i18n.com/dingyufei615/ai-code-review-helper?lang=es) | [Français](https://www.readme-i18n.com/dingyufei615/ai-code-review-helper?lang=fr) | [한국어](https://www.readme-i18n.com/dingyufei615/ai-code-review-helper?lang=ko) | [Português](https://www.readme-i18n.com/dingyufei615/ai-code-review-helper?lang=pt) | [Русский](https://www.readme-i18n.com/dingyufei615/ai-code-review-helper?lang=ru)

> 监听 GitHub/GitLab PR/MR → LLM 自动 Review → 评论 + 通知，一站式完成。  
>
> [B 站 3 分钟上手演示](https://www.bilibili.com/video/BV1TF7ozaEPv)

## ✨ 核心能力
| 场景 | 详细审查模式 `/webhook` | 通用审查模式 `/webhook_general` |
|---|---|---|
| **目标** | 逐行找问题，JSON 结构化输出 | 每文件一段 Markdown 总结 |
| **评论粒度** | 多评论，可定位行号 | 单评论 |
| **模型要求** | 强指令遵循（GPT-4、Kimi 等） | 任意 LLM |
| **失败兜底** | 自动降级为通用模式 | 始终输出 |

## 🚀 启动

### Docker


```bash
docker run -d --name ai-coder \
  -p 8088:8088 \
  -e ADMIN_API_KEY=change_me \
  -e OPENAI_API_KEY=$YOUR_KIMI_KEY \
  -e REDIS_HOST=redis \
  --link redis:redis \
  dingyufei/ai-code-review-helper:latest
```
> 唯一必须改的变量：`ADMIN_API_KEY` 和 `OPENAI_API_KEY`。Redis 若在外部，把 `--link` 换成 `-e REDIS_HOST=xxx`。

### 本地

执行如下命令

```bash
git clone https://github.com/dingyufei615/ai-code-review-helper.git
cd ai-code-review-helper
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # 填写密钥
python -m api.ai_code_review_helper

## 安装redis
docker run -d --name redis -p 6379:6379 redis:latest
```

填写配置.env

```bash
# Admin API Key for accessing management panel and APIs
ADMIN_API_KEY=123456

# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8088

# LLM Configuration (OpenAI Compatible - Kimi)
OPENAI_API_BASE_URL=https://api.moonshot.cn/v1
OPENAI_MODEL=kimi-k2-turbo-preview
OPENAI_API_KEY=sk-xxx

# VCS API URLs (usually don't need to change)
GITHUB_API_URL=https://api.github.com
GITLAB_INSTANCE_URL=https://gitlab.com

# Notification Webhooks (optional)
WECOM_BOT_WEBHOOK_URL=
CUSTOM_WEBHOOK_URL=

# GitHub Webhook
GITHUB_WEBHOOK_SECRET=xxx
GITHUB_ACCESS_TOKEN=ghp_xxx

# Redis Configuration (Local development - disable SSL)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_SSL_ENABLED=false
REDIS_DB=0

```


## 🔧 管理面板 
- 地址：`http://<host>:8088/admin`  
- 用途：增删仓库、改密钥、调模型、看记录  
- 认证：Header `X-Admin-API-Key` = `ADMIN_API_KEY`
