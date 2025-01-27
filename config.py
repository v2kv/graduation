import os
import stripe # simulate payments

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'GRADUATION')  # Get secret key from environment variables
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'mysql+pymysql://ahmed:12345678@data/graduation'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Disable SQLAlchemy event system
    ADMIN_REGISTRATION_TOKEN = os.environ.get('ADMIN_REGISTRATION_TOKEN', 'GRADUATION')  # Get admin registration token from environment variables

    stripe.api_key = "sk_test_51QhcQwGK7HgCufdXVD0auQv4NGn8qm9TRWXRYlVoPkrvzzoI7WVmE9SYsIMH0zCn6fov7hlyvs0dp8Ra7kv4TC1r00HXsSH5ap" # stripe test secret key

    MAIL_SERVER = 'smtp.example.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'your_email@example.com'
    MAIL_PASSWORD = 'your_email_password'
    MAIL_DEFAULT_SENDER = 'your_email@example.com'
  
