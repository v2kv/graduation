from db import db
from werkzeug.security import generate_password_hash, check_password_hash

class Admin(db.Model):
    __tablename__ = 'admins'
    admin_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False, default='admin')
    created_at = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    user_email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp())
    is_active = db.Column(db.Boolean, nullable=False, default=True)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)