import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')  # Get secret key from environment variables
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'mysql+pymysql://ahmed:12345678@localhost/graduation'  
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Disable SQLAlchemy event system