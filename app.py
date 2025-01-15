from flask import Flask, render_template
from config import Config
from db import db
from routes import index_bp, admin_bp, user_bp, item_bp, cart_bp, order_bp
from flask_login import LoginManager
from dotenv import load_dotenv
from flask_mail import Mail

load_dotenv()  # Load environment variables from .env

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'user.user_login'

mail = Mail(app)

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
app.register_blueprint(order_bp)

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
    app.run(debug=True)