from flask import current_app, request
from app.models import LoginAttempt, db
from app.services.device_fingerprint import get_device_fingerprint  # 正确路径

def log_auth_event(user_id, event_type, risk_score=None):
    try:
        log_entry = LoginAttempt(
            user_id=user_id,
            ip_address=request.remote_addr,
            device_fingerprint=get_device_fingerprint(request),
            event_type=event_type,
            risk_score=risk_score,
            was_successful=True
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(f"Logging failed: {str(e)}")