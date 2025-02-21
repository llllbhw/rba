from flask import Blueprint, render_template, request, redirect, url_for
from flask_login import login_user, logout_user, login_required
from app import db
from app.models import User, LoginAttempt
from app.services.log_service import log_auth_event       # 从services导入
from app.services.device_fingerprint import get_device_fingerprint
from app.services.geo_ip import get_geo_location
from app.rba.risk_engine import RiskEngine               # 从rba导入
auth_bp = Blueprint('auth', __name__)
from flask import current_app  # 替代直接导入app
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            device_fp = get_device_fingerprint(request)
            geo_info = get_geo_location(request.remote_addr)
            
            # 风险评估
            risk_score = current_app.risk_engine.evaluate(
                user=user,
                device_fp=device_fp,
                geo_info=geo_info
            )
            
            # 记录登录尝试
            login_attempt = LoginAttempt(
                user_id=user.id,
                ip_address=request.remote_addr,
                device_fingerprint=device_fp,
                risk_score=risk_score,
                was_successful=True
            )
            db.session.add(login_attempt)
            db.session.commit()
            
            log_auth_event(user.id, 'LOGIN_ATTEMPT', risk_score)
            
            if risk_score > current_app.config['HIGH_RISK_THRESHOLD']:
                return redirect(url_for('auth.mfa_verify'))
            
            login_user(user)
            return redirect(url_for('auth.dashboard'))
            
        return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@auth_bp.route('/mfa/verify', methods=['GET', 'POST'])
def mfa_verify():
    # TOTP或WebAuthn验证逻辑
    pass

@auth_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@auth_bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('auth.login'))