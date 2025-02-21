from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120))
    mfa_enabled = db.Column(db.Boolean, default=False)
    totp_secret = db.Column(db.String(32))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime, nullable=False)
    ip_address = db.Column(db.String(45))
    device_fingerprint = db.Column(db.String(64))
    risk_score = db.Column(db.Float)
    was_successful = db.Column(db.Boolean)

class DeviceFingerprint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    fingerprint_hash = db.Column(db.String(64), unique=True)
    last_used = db.Column(db.DateTime)

class GeoLocation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True)
    country = db.Column(db.String(64))
    city = db.Column(db.String(64))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)