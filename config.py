import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'GRADUATION')  # Get secret key from environment variables
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'mysql+pymysql://ahmed:12345678@localhost/graduation'  
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Disable SQLAlchemy event system
    ADMIN_REGISTRATION_TOKEN = os.environ.get('ADMIN_REGISTRATION_TOKEN', 'GRADUATION')  # Get admin registration token from environment variables