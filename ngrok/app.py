import logging
import hmac
import hashlib
import os
from flask import Flask, request, jsonify
from dotenv import load_dotenv
# 测试 ngrok 的能力
# 加载 .env 文件
load_dotenv()

app = Flask(__name__)

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 从环境变量加载 GitHub Webhook Secret
GITHUB_WEBHOOK_SECRET = os.getenv('GITHUB_WEBHOOK_SECRET')
SECRET = GITHUB_WEBHOOK_SECRET.encode()

@app.route('/github-webhook', methods=['POST'])
def github_webhook():
    """处理 GitHub Webhook 请求"""
    try:
        # 1. 校验签名
        signature = request.headers.get('X-Hub-Signature-256', '')
        if not signature:
            logger.warning("缺少 X-Hub-Signature-256 头部")
            return jsonify(error="Missing signature"), 401

        mac = hmac.new(SECRET, request.get_data(), hashlib.sha256).hexdigest()
        expected_signature = f'sha256={mac}'
        if not hmac.compare_digest(expected_signature, signature):
            logger.warning("签名验证失败")
            return jsonify(error="Invalid signature"), 401

        # 2. 获取事件类型和数据
        event = request.headers.get('X-GitHub-Event')
        if not event:
            logger.warning("缺少 X-GitHub-Event 头部")
            return jsonify(error="Missing event type"), 400

        try:
            payload = request.get_json()
        except Exception as e:
            logger.error(f"解析 JSON 负载失败: {e}")
            return jsonify(error="Invalid JSON payload"), 400

        # 3. 处理事件
        logger.info(f"收到 GitHub 事件: {event}")

        if event == 'ping':
            logger.info("收到 ping 事件 - Webhook 配置测试")
            return jsonify(ok=True, message="Webhook ping received")
        elif event in ['push', 'pull_request']:
            logger.info(f"处理 {event} 事件")
            # 打印关键信息
            if event == 'push':
                ref = payload.get('ref', '')
                repository = payload.get('repository', {}).get('full_name', '')
                logger.info(f"Push 到 {ref} 在仓库 {repository}")
            elif event == 'pull_request':
                action = payload.get('action', '')
                pr_number = payload.get('pull_request', {}).get('number', '')
                repository = payload.get('repository', {}).get('full_name', '')
                logger.info(f"PR #{pr_number} {action} 在仓库 {repository}")

            # 这里可以添加更多处理逻辑，如触发代码审查

        else:
            logger.info(f"收到未处理的事件类型: {event}")

        return jsonify(ok=True, event=event)

    except Exception as e:
        logger.error(f"处理 Webhook 时发生错误: {e}")
        return jsonify(error="Internal server error"), 500

@app.route('/health', methods=['GET'])
def health_check():
    """健康检查端点"""
    return jsonify(status="healthy", service="github-webhook-tester")

if __name__ == '__main__':
    port = int(os.getenv('WEBHOOK_TEST_PORT', 8087))
    logger.info(f"启动 GitHub Webhook 测试服务于端口 {port}")
    app.run(host='0.0.0.0', port=port, debug=True)
