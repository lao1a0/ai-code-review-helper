---
name: python-language-guide
version: 1.0.0
description: Python语言安全最佳实践和常见漏洞模式
language: python
tags: [python, security, best-practices, vulnerabilities]
frameworks: [django, flask, fastapi]
---

# Python语言安全指南

## 概述
本指南涵盖Python开发中的安全最佳实践、常见漏洞模式以及防御措施，适用于Web应用、API服务和数据处理应用。

## 安全编码实践

### 1. 输入验证与清理
```python
# ❌ 不安全的做法
user_input = request.args.get('name')
query = f"SELECT * FROM users WHERE name = '{user_input}'"

# ✅ 安全的做法
from sqlalchemy import text
user_input = request.args.get('name')
if not user_input or not user_input.isalnum():
    raise ValueError("Invalid input")
query = text("SELECT * FROM users WHERE name = :name")
result = db.session.execute(query, {"name": user_input})
```

### 2. SQL注入防护
```python
# ❌ 直接字符串拼接
def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query).fetchone()

# ✅ 使用参数化查询
def get_user_safe(username):
    query = "SELECT * FROM users WHERE username = %s"
    return db.execute(query, (username,)).fetchone()

# ✅ 使用ORM
class User(db.Model):
    username = db.Column(db.String(80), unique=True)
    
    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()
```

### 3. 命令注入防护
```python
# ❌ 直接执行用户输入
import os
filename = request.args.get('file')
os.system(f"cat {filename}")

# ✅ 使用安全的方法
import subprocess
from pathlib import Path

def read_file_safe(filename):
    # 验证文件路径
    base_path = Path("/safe/directory")
    file_path = (base_path / filename).resolve()
    
    if not str(file_path).startswith(str(base_path)):
        raise ValueError("Invalid file path")
    
    if not file_path.exists():
        raise FileNotFoundError("File not found")
    
    return file_path.read_text()

# ✅ 使用subprocess with shell=False
def run_command_safe(command_args):
    try:
        result = subprocess.run(
            command_args,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Command failed: {e.stderr}")
```

### 4. 反序列化安全
```python
# ❌ 不安全的反序列化
import pickle
data = request.get_data()
obj = pickle.loads(data)  # 危险！

# ✅ 使用安全的序列化格式
import json
data = request.get_json()
# 验证数据结构
if not isinstance(data, dict):
    raise ValueError("Invalid data format")

# ✅ 使用受限的pickle
import pickle
import io

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        # 只允许特定的类
        if module == "builtins" and name in {"str", "int", "float", "list", "dict"}:
            return getattr(builtins, name)
        raise pickle.UnpicklingError(f"Attempting to load an unknown class '{name}'")

def safe_unpickle(data):
    return RestrictedUnpickler(io.BytesIO(data)).load()
```

## 常见安全漏洞

### 1. 路径遍历
```python
# ❌ 路径遍历漏洞
import os
filename = request.args.get('filename')
file_path = os.path.join('/uploads', filename)
return send_file(file_path)

# ✅ 安全的路径处理
from werkzeug.utils import secure_filename
import os

def get_safe_file_path(filename):
    # 清理文件名
    safe_filename = secure_filename(filename)
    
    # 限制目录
    base_dir = os.path.abspath('/app/uploads')
    file_path = os.path.abspath(os.path.join(base_dir, safe_filename))
    
    # 确保文件在指定目录内
    if not file_path.startswith(base_dir):
        raise ValueError("Invalid file path")
    
    return file_path
```

### 2. XML外部实体(XXE)
```python
# ❌ 易受XXE攻击
import xml.etree.ElementTree as ET
xml_data = request.get_data()
root = ET.fromstring(xml_data)

# ✅ 安全的XML解析
import defusedxml.ElementTree as ET
from defusedxml import DefusedXmlException

def parse_xml_safe(xml_data):
    try:
        root = ET.fromstring(xml_data)
        return root
    except DefusedXmlException as e:
        raise ValueError(f"Invalid XML: {str(e)}")

# ✅ 使用lxml并禁用实体
from lxml import etree

def parse_xml_lxml_safe(xml_data):
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        dtd_validation=False
    )
    try:
        root = etree.fromstring(xml_data, parser=parser)
        return root
    except etree.XMLSyntaxError as e:
        raise ValueError(f"Invalid XML: {str(e)}")
```

### 3. 服务器端模板注入(SSTI)
```python
# ❌ Jinja2 SSTI漏洞
from jinja2 import Template
user_input = request.args.get('template')
template = Template(user_input)
rendered = template.render()

# ✅ 安全的模板渲染
from jinja2 import Environment, select_autoescape

def render_template_safe(template_str, context):
    env = Environment(
        autoescape=select_autoescape(['html', 'xml']),
        loader=None  # 禁用文件加载
    )
    
    # 限制可用的过滤器
    env.filters = {
        'safe': lambda x: x,  # 只允许安全的过滤器
    }
    
    template = env.from_string(template_str)
    return template.render(**context)

# ✅ 使用Django模板
from django.template import engines

def render_django_template(template_str, context):
    template = engines['django'].from_string(template_str)
    return template.render(context)
```

### 4. 反序列化漏洞
```python
# ❌ 使用pickle反序列化用户输入
import pickle
user_data = request.get_data()
obj = pickle.loads(user_data)

# ✅ 使用JSON
import json
user_data = request.get_json()
# 验证数据结构
if not isinstance(user_data, dict):
    raise ValueError("Invalid data format")

# ✅ 使用marshmallow验证
from marshmallow import Schema, fields, validate

class UserSchema(Schema):
    username = fields.Str(required=True, validate=validate.Length(min=3, max=50))
    email = fields.Email(required=True)
    age = fields.Int(required=True, validate=validate.Range(min=1, max=120))

def validate_user_data(data):
    schema = UserSchema()
    try:
        return schema.load(data)
    except ValidationError as err:
        raise ValueError(f"Invalid data: {err.messages}")
```

## Web框架安全

### 1. Django安全实践
```python
# settings.py安全配置
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
X_FRAME_OPTIONS = 'DENY'

# 安全的查询
from django.db.models import Q

def search_users_safe(query):
    # 使用ORM防止SQL注入
    return User.objects.filter(
        Q(username__icontains=query) | 
        Q(email__icontains=query)
    )

# CSRF保护
from django.views.decorators.csrf import csrf_protect

@csrf_protect
@require_http_methods(["POST"])
def update_profile(request):
    if request.method == 'POST':
        form = ProfileForm(request.POST)
        if form.is_valid():
            form.save()
            return JsonResponse({'success': True})
    return JsonResponse({'error': 'Invalid form'}, status=400)
```

### 2. Flask安全实践
```python
from flask import Flask, request, jsonify
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
csrf = CSRFProtect(app)

# 速率限制
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# 输入验证
from wtforms import Form, StringField, validators

class LoginForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = StringField('Password', [validators.Length(min=6, max=35)])

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm(request.form)
    if form.validate():
        # 处理登录
        return jsonify({'success': True})
    return jsonify({'errors': form.errors}), 400

# 安全的文件上传
import os
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = '/app/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        return jsonify({'success': True})
    
    return jsonify({'error': 'Invalid file type'}), 400
```

### 3. FastAPI安全实践
```python
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, validator
import jwt

app = FastAPI()
security = HTTPBearer()

# 输入验证模型
class UserCreate(BaseModel):
    username: str
    email: str
    
    @validator('username')
    def username_alphanumeric(cls, v):
        if not v.isalnum():
            raise ValueError('Username must be alphanumeric')
        return v
    
    @validator('email')
    def email_valid(cls, v):
        if '@' not in v:
            raise ValueError('Invalid email format')
        return v

# JWT验证
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/users")
async def create_user(user: UserCreate, current_user: dict = Depends(verify_token)):
    # 创建用户逻辑
    return {"message": "User created successfully"}

# 依赖注入安全
from sqlalchemy.orm import Session

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/users/{user_id}")
def read_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user
```

## 密码学最佳实践

### 1. 密码哈希
```python
# ❌ 使用弱哈希
import hashlib
password = "user_password"
hashed = hashlib.md5(password.encode()).hexdigest()

# ✅ 使用bcrypt
import bcrypt

def hash_password(password: str) -> str:
    """安全地哈希密码"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """验证密码"""
    return bcrypt.checkpw(
        password.encode('utf-8'),
        hashed.encode('utf-8')
    )

# ✅ 使用argon2
from argon2 import PasswordHasher

ph = PasswordHasher()
hash = ph.hash("user_password")
try:
    ph.verify(hash, "user_password")
    print("Valid password")
except:
    print("Invalid password")
```

### 2. 加密敏感数据
```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

def generate_key_from_password(password: str, salt: bytes = None) -> bytes:
    """从密码生成加密密钥"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_sensitive_data(data: str, password: str) -> tuple:
    """加密敏感数据"""
    key, salt = generate_key_from_password(password)
    f = Fernet(key)
    encrypted = f.encrypt(data.encode())
    return encrypted, salt

def decrypt_sensitive_data(encrypted_data: bytes, password: str, salt: bytes) -> str:
    """解密敏感数据"""
    key, _ = generate_key_from_password(password, salt)
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_data)
    return decrypted.decode()
```

## 日志与监控

### 1. 安全日志记录
```python
import logging
import json
from datetime import datetime

class SecurityLogger:
    def __init__(self):
        self.logger = logging.getLogger('security')
        handler = logging.FileHandler('security.log')
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def log_authentication(self, username: str, success: bool, ip: str):
        """记录认证事件"""
        event = {
            "event_type": "authentication",
            "username": username,
            "success": success,
            "ip_address": ip,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.logger.info(json.dumps(event))
    
    def log_authorization(self, user_id: int, resource: str, action: str, granted: bool):
        """记录授权事件"""
        event = {
            "event_type": "authorization",
            "user_id": user_id,
            "resource": resource,
            "action": action,
            "granted": granted,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.logger.info(json.dumps(event))

# 使用示例
security_logger = SecurityLogger()
security_logger.log_authentication("admin", True, "192.168.1.100")
```

### 2. 异常监控
```python
from functools import wraps
import traceback

def monitor_security_events(func):
    """装饰器监控安全相关函数"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return result
        except Exception as e:
            # 记录异常
            logger.error(f"Security exception in {func.__name__}: {str(e)}")
            logger.error(traceback.format_exc())
            raise
    return wrapper

@monitor_security_events
def process_user_upload(file_data):
    # 处理用户上传
    pass
```

## 安全测试

### 1. 静态代码分析
```python
# 使用bandit进行安全检查
# pip install bandit
# bandit -r your_project/

# 使用pylint安全插件
# pip install pylint-plugin-utils
# pylint --load-plugins=pylint_secure_coding_standards your_project/
```

### 2. 依赖安全检查
```python
# 使用safety检查依赖漏洞
# pip install safety
# safety check

# 使用pip-audit
# pip install pip-audit
# pip-audit
```

### 3. 动态测试
```python
# 使用OWASP ZAP
# 使用Burp Suite进行安全测试
```

## 安全工具推荐

### 1. 静态分析工具
- **bandit**: Python安全漏洞扫描
- **semgrep**: 多语言静态分析
- **pylint**: 代码质量检查
- **mypy**: 类型检查

### 2. 依赖管理
- **pip-audit**: 依赖漏洞扫描
- **safety**: 已知漏洞检查
- **pip-licenses**: 许可证检查

### 3. 运行时保护
- **fail2ban**: 暴力破解防护
- **mod_security**: Web应用防火墙
- **osquery**: 系统监控

## 参考资源

- [OWASP Python Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Python_Security_Cheat_Sheet.html)
- [Python Security Best Practices](https://python.org/dev/security/)
- [Django Security Documentation](https://docs.djangoproject.com/en/stable/topics/security/)
- [Flask Security Considerations](https://flask.palletsprojects.com/en/latest/security/)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)
