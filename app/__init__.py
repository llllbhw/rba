from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()

def create_app(config_class='app.config.Config'):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    with app.app_context():
        from app.routes import auth_bp
        app.register_blueprint(auth_bp)

        from app.rba.risk_engine import RiskEngine
        app.risk_engine = RiskEngine(config=app.config, driver=None)  # 需补充实际driver实现

        db.create_all()

    return app