"""
Authentication routes
"""
import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from core.services.auth import get_auth_service

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
auth_service = get_auth_service()

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('请输入用户名和密码', 'error')
            return render_template('login.html')
        
        user = auth_service.authenticate_user(username, password)
        if user:
            if auth_service.login(user):
                return redirect(url_for('console.index'))
            else:
                flash('登录失败，请重试', 'error')
        else:
            flash('用户名或密码错误', 'error')
    
    return render_template('login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not all([username, email, password, confirm_password]):
            flash('请填写所有必填字段', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('两次输入的密码不一致', 'error')
            return render_template('register.html')
        
        if not password or len(password) < 6:
            flash('密码长度至少为6位', 'error')
            return render_template('register.html')
        
        # Create user
        if username and email and password:
            user = auth_service.create_user(username, email, password)
        else:
            user = None
        if user:
            flash('注册成功，请登录', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('用户名或邮箱已存在', 'error')
    
    return render_template('register.html')

@auth_bp.route('/logout')
@login_required
def logout():
    """User logout"""
    auth_service.logout()
    flash('您已成功退出登录', 'success')
    return redirect(url_for('auth.login'))
