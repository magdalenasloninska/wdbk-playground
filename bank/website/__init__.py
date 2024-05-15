import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_manager
from flask_migrate import Migrate
from argon2 import PasswordHasher
from oauthlib.oauth2 import WebApplicationClient
import requests
from sqlalchemy import MetaData


naming_convention = {
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(column_0_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

db = SQLAlchemy(metadata=MetaData(naming_convention=naming_convention))
ph = PasswordHasher()
APP_NAME = "Bank"
DB_NAME = "database.db"

# OAuth2 initial configuration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", '')
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", '')
GOOGLE_DISCOVERY_URL = ("https://accounts.google.com/.well-known/openid-configuration")
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

client = WebApplicationClient(GOOGLE_CLIENT_ID)

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'guma balonowa'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    db.init_app(app)

    migrate = Migrate(app, db, render_as_batch=True)
    
    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')
    
    from .models import User, Transfer

    with app.app_context():
        db.create_all()
        print('Created database!')

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(id)

    return app
