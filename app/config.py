import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEBUG = False
    TESTING = False
    
    # RBA 配置
    HIGH_RISK_THRESHOLD = 0.7
    MEDIUM_RISK_THRESHOLD = 0.4
    GEOIP_DATABASE_PATH = 'GeoLite2-City.mmdb'
    
    # 安全配置
    SESSION_COOKIE_SECURE = True
    CSRF_ENABLED = True
    # 添加风险引擎配置
    RISK_FEATURES = ['ip', 'ua']
    IP_WEIGHT = 0.4
    DEVICE_WEIGHT = 0.3
    BEHAVIOR_WEIGHT = 0.3
    REJECT_THRESHOLD = 0.9
    REQUEST_THRESHOLD = 0.7

class ProductionConfig(Config):
    DEBUG = False

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_ECHO = True

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'