from flask import Flask
from config import Config
from db import db
from routes import index_bp,admin_bp, user_bp
from flask_login import LoginManager
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'user.user_login'

@login_manager.user_loader
def load_user(user_id):
    from models import Admin, User
    return Admin.query.get(int(user_id)) or User.query.get(int(user_id))

# Register Blueprints
app.register_blueprint(index_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(user_bp)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables in MySQL
    app.run(debug=True)