from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'GRADUATION')  # Get secret key from environment variables
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'mysql+pymysql://ahmed:12345678@127.0.0.1/graduation'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Disable SQLAlchemy event system
    ADMIN_REGISTRATION_TOKEN = os.environ.get('ADMIN_REGISTRATION_TOKEN', 'GRADUATION')  # Get admin registration token from environment variables

    STRIPE_PUBLIC_KEY = os.environ.get('STRIPE_PUBLIC_KEY', 'pk_test_51QhcQwGK7HgCufdX8dCTXfvu5nc28q4xxPDMPXvyHwAgOvE46T6Mu0P8PMfM3cFTEDTglBmJyVtDRFZv0PjIO6n000ztEGQoGZ')
    STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY', 'sk_test_51QhcQwGK7HgCufdXVD0auQv4NGn8qm9TRWXRYlVoPkrvzzoI7WVmE9SYsIMH0zCn6fov7hlyvs0dp8Ra7kv4TC1r00HXsSH5ap')

    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'souqkhana@gmail.com'
    MAIL_PASSWORD = 'hwft gpgv egnk vudj'
    MAIL_DEFAULT_SENDER = 'no-reply@souqkhana.com'

    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
    GOOGLE_REDIRECT_URI = 'https://127.0.0.1:5000/login/google/authorized'