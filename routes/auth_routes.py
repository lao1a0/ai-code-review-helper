from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash

from db.models import db
from db.models.user import User

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    """用户登录"""
    if request.method == 'GET':
        return render_template('login.html')
    
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            if request.is_json:
                return jsonify({'error': '用户名和密码不能为空'}), 400
            flash('用户名和密码不能为空', 'error')
            return redirect(url_for('auth.login'))
        
        # 查找用户
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            if request.is_json:
                return jsonify({'error': '用户名或密码错误'}), 401
            flash('用户名或密码错误', 'error')
            return redirect(url_for('auth.login'))
        
        # 登录用户
        login_user(user)
        
        if request.is_json:
            return jsonify({
                'message': '登录成功',
                'user': user.to_dict()
            })
        
        flash('登录成功', 'success')
        return redirect(url_for('console_app.console_page'))

@bp.route('/register', methods=['GET', 'POST'])
def register():
    """用户注册"""
    if request.method == 'GET':
        return render_template('register.html')
    
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        
        username = data.get('username', '').strip()
        nickname = data.get('nickname', '').strip()
        password = data.get('password', '')
        
        if not username or not nickname or not password:
            if request.is_json:
                return jsonify({'error': '所有字段都是必填的'}), 400
            flash('所有字段都是必填的', 'error')
            return redirect(url_for('auth.register'))
        
        # 检查用户名是否已存在
        if User.query.filter_by(username=username).first():
            if request.is_json:
                return jsonify({'error': '用户名已存在'}), 400
            flash('用户名已存在', 'error')
            return redirect(url_for('auth.register'))
        
        # 创建新用户
        user = User(username=username, nickname=nickname)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        if request.is_json:
            return jsonify({
                'message': '注册成功',
                'user': user.to_dict()
            }), 201
        
        flash('注册成功，请登录', 'success')
        return redirect(url_for('auth.login'))

@bp.route('/logout')
@login_required
def logout():
    """用户登出"""
    logout_user()
    flash('您已成功退出登录', 'success')
    return redirect(url_for('auth.login'))

@bp.route('/profile')
@login_required
def profile():
    """用户资料"""
    return jsonify(current_user.to_dict())
