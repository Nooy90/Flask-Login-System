from flask_login import LoginManager
from .admin import admin_routes
from .auth import auth_routes
from .seller import seller_routes
from .buyer import buyer_routes
from app.database import setup_db
from app.login import login_manager
from flask import Blueprint, Flask

app = Flask(__name__)
app.secret_key = '904872903489023kldnkansdkj0923480932'
app.debug = True

app.register_blueprint(admin_routes.admin_bp)
app.register_blueprint(auth_routes.auth_bp)
app.register_blueprint(seller_routes.seller_bp)
app.register_blueprint(buyer_routes.buyer_bp)

setup_db(app)
login_manager.init_app(app)