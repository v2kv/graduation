from flask import Flask, render_template, current_app
import os
from config import Config
from db import db, mail
from routes import index_bp, admin_bp, user_bp, item_bp, cart_bp, order_bp, wishlist_bp
from flask_login import LoginManager
from dotenv import load_dotenv
from flask_dance.contrib.google import make_google_blueprint, google
import logging
load_dotenv()  # Load environment variables from .env
app = Flask(__name__)
app.config.from_object(Config)

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# app.run(debug=True, port=5500)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'user.user_login'

mail.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    from flask import session
    from models import Admin, User

    # Determine user type from the session
    user_type = session.get('user_type')
    if user_type == 'admin':
        return Admin.query.get(int(user_id))
    elif user_type == 'user':
        return User.query.get(int(user_id))
    return None  # If no user is found

google_bp = make_google_blueprint(
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    scope=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_url=app.config['GOOGLE_REDIRECT_URI'],
    redirect_to="user.user_register"
)
app.register_blueprint(google_bp, url_prefix="/login")

# Register Blueprints
app.register_blueprint(index_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(user_bp)
app.register_blueprint(item_bp)
app.register_blueprint(cart_bp)
app.register_blueprint(wishlist_bp)
app.register_blueprint(order_bp)

@app.context_processor
def inject_current_app():
    return dict(current_app=current_app)

# error handlers

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables in MySQL
    app.run(debug=True, port=5501, ssl_context=('cert.pem', 'key.pem'))