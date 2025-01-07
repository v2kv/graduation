import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-default-secret-key')  # Get secret key from environment variables or use a default value
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'mysql+pymysql://ahmed:12345678@localhost/graduation'  
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Disable SQLAlchemy event system