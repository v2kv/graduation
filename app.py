from flask import Flask, render_template, current_app
import os
from config import Config
from db import db, mail
# Import blueprints from the routes package
from routes import index_bp, admin_bp, user_bp, item_bp, cart_bp, order_bp, wishlist_bp
from flask_login import LoginManager
from dotenv import load_dotenv
from flask import g
from flask_login import current_user
from models import ShoppingCart
import logging
from logging.handlers import RotatingFileHandler
import sys

load_dotenv()  # Load environment variables from .env

# Create Flask application
def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Configure logging
    if not app.debug and not app.testing:
        # Create logs directory if it doesn't exist
        if not os.path.exists('logs'):
            os.mkdir('logs')
        
        # Configure file handler for app.log
        file_handler = RotatingFileHandler('logs/souqkhana.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        
        # Add handlers to app logger
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('SOUQKHANA startup')
        
        # Also log to console
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        app.logger.addHandler(console_handler)

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

    # Register Blueprints
    app.register_blueprint(index_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(item_bp)
    app.register_blueprint(cart_bp)
    app.register_blueprint(wishlist_bp)
    app.register_blueprint(order_bp)

    @app.context_processor
    def inject_cart():
        """Make cart available in all templates"""
        if current_user.is_authenticated and current_user.role != 'admin':
            cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
            return {'cart': cart}  # Inject `cart` into all templates
        return {'cart': None}  # No cart if not logged in
        
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
        
    return app

# Create application instance for running directly
app = create_app()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables in MySQL
    app.run(debug=True, port=5000, ssl_context=('cert.pem', 'key.pem'))