import os
import re
import stripe
import requests
from stripe.error import StripeError
from flask import Blueprint, session, request, render_template, flash, redirect, url_for, current_app, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from db import db, mail
from models import Admin, User, Item, ShoppingCart, CartItem, Wishlist, WishlistItem, Order, Category, Tag, ItemTag, ProductImage, Address, PaymentMethod, Messages
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy import or_, and_
from sqlalchemy.orm import joinedload
from sqlalchemy.exc import IntegrityError
from db import reset_auto_increment, allowed_file, upload_image, delete_image
from itsdangerous import TimedSerializer as Serializer
from itsdangerous import SignatureExpired, BadSignature
from flask_mail import Message

# Admin required decorator
def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You do not have permission to access this page.', 'warning')
            return redirect(url_for('index.index'))
        return func(*args, **kwargs)
    return decorated_view

# Email confirmation function
def send_confirmation_email(email, token, user_type):
    msg = Message('Confirm Your Email',
                  sender=current_app.config['MAIL_DEFAULT_SENDER'],
                  recipients=[email])
    
    if user_type == 'admin':
        confirmation_url = url_for('admin.confirm_email', token=token, _external=True)
    else:
        confirmation_url = url_for('user.confirm_email', token=token, _external=True)
        
    msg.html = render_template('emails/confirmation.html', confirmation_url=confirmation_url)
    mail.send(msg)

# Helper function for categories
def get_all_subcategories(category):
    """Helper function to recursively get IDs of all subcategories of a given category."""
    subcategories = []
    def gather_subcategories(cat):
        for sub in cat.subcategories:
            subcategories.append(sub)
            gather_subcategories(sub)
    gather_subcategories(category)
    return subcategories

# Generate slugs for categories
def generate_slug(name):
    """Convert category names into URL-friendly slugs (lowercase, hyphenated)."""
    return re.sub(r'\W+', '-', name.strip().lower()).strip('-')

# Default country and Iraqi governorates
DEFAULT_COUNTRY = "Iraq"
IRAQ_GOVERNORATES = [
    "Baghdad", "Basra", "Nineveh", "Kirkuk", "Erbil", "Sulaymaniyah", "Duhok",
    "Anbar", "Babylon", "Dhi Qar", "Karbala", "Najaf", "Maysan", "Wasit",
    "Qadisiyah", "Muthanna", "Salah ad-Din", "Diyala"
]