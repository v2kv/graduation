import os
from flask import Blueprint, session, request, render_template, flash, redirect, url_for, current_app
from flask_login import login_user, logout_user, login_required, current_user
import pycountry # list of all countries for address
import re # check phone number format
import stripe # simulate payments
from db import db
from models import Admin, User, Item, ShoppingCart, CartItem, Order, Category, OrderItem, Tag, ItemTag, ProductImage, Address, PaymentMethod
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy.orm import joinedload
from db import reset_auto_increment, allowed_file, upload_image, delete_image # functions I defined in db.py

# Blueprints
index_bp = Blueprint('index', __name__)
admin_bp = Blueprint('admin', __name__)
user_bp = Blueprint('user', __name__)
item_bp = Blueprint('item', __name__)
cart_bp = Blueprint('cart', __name__)
order_bp = Blueprint('order', __name__)

# admin required flag for routes only accessible by admins

def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You do not have permission to access this page.', 'warning')
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    return decorated_view


@index_bp.route('/')
def index():
    items = Item.query.options(joinedload(Item.images)).all()
    return render_template('index.html', items=items)

# Admin Routes
@admin_bp.route('/admin/register/<secret_token>', methods=['GET', 'POST'])
def admin_register(secret_token):
    if secret_token != current_app.config['ADMIN_REGISTRATION_TOKEN']:
        flash('Invalid registration token!', 'danger')
        return redirect(url_for('index.index'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        password_hash = generate_password_hash(password)

        if Admin.query.filter((Admin.username == username) | (Admin.email == email)).first():
            flash('Username or email already exists!', 'danger')
            return redirect(url_for('admin.admin_register', secret_token=secret_token))

        new_admin = Admin(username=username, email=email, password_hash=password_hash)
        db.session.add(new_admin)
        db.session.commit()

        flash('Admin registered successfully!', 'success')
        return redirect(url_for('admin.admin_login'))

    return render_template('admin/admin_register.html', secret_token=secret_token)

@admin_bp.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.verify_password(password):
            login_user(admin)
            # Set user type to admin in the session
            session['user_type'] = 'admin'
            flash('Login successful!', 'success')
            return redirect(url_for('admin.admin_dashboard'))

        flash('Invalid username or password', 'danger')

    return render_template('admin/admin_login.html')

@admin_bp.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index.index'))

@admin_bp.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin/admin_dashboard.html')

# admin functionalities

# categories

@admin_bp.route('/admin/categories')
@login_required
@admin_required
def manage_categories():
    categories = Category.query.all()
    return render_template('admin/manage_categories.html', categories=categories)

@admin_bp.route('/admin/categories/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_category():
    if request.method == 'POST':
        category_name = request.form['category_name']
        parent_category_id = request.form['parent_category_id']
        
        if parent_category_id == '':
            parent_category_id = None
        
        new_category = Category(category_name=category_name, parent_category_id=parent_category_id)
        db.session.add(new_category)
        db.session.commit()

        flash('Category added successfully', 'success')
        return redirect(url_for('admin.manage_categories'))
    
    parent_categories = Category.query.all()
    return render_template('admin/add_category.html', parent_categories=parent_categories)

@admin_bp.route('/admin/categories/<int:category_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_category(category_id):
    category = Category.query.get_or_404(category_id)
    if request.method == 'POST':
        category.category_name = request.form['category_name']
        category.parent_category_id = request.form['parent_category_id']
        db.session.commit()
        flash('Category updated successfully', 'success')
        return redirect(url_for('admin.manage_categories')) 
    parent_categories = Category.query.all()
    return render_template('admin/edit_category.html', category=category, parent_categories=parent_categories)

@admin_bp.route('/admin/categories/<int:category_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    db.session.delete(category)
    db.session.commit()
    reset_auto_increment(db, 'categories', 'category_id')
    flash('Category deleted successfully', 'success')
    return redirect(url_for('admin.manage_categories'))  

# items

@admin_bp.route('/admin/items')
@login_required
@admin_required
def manage_items():
    items = Item.query.all()
    return render_template('admin/manage_items.html', items=items)

@admin_bp.route('/admin/items/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_item():
    if request.method == 'POST':
        item_name = request.form['item_name']
        item_description = request.form['item_description']
        item_price = request.form['item_price']
        category_id = request.form['category_id']
        tag_ids = request.form.getlist('tags')
        
        new_item = Item(item_name=item_name, item_description=item_description, item_price=item_price, category_id=category_id)
        db.session.add(new_item)
        db.session.commit()

        for tag_id in tag_ids:
            item_tag = ItemTag(item_id=new_item.item_id, tag_id=tag_id)
            db.session.add(item_tag)

        if 'image' in request.files:
            image = request.files['image']
            if image and allowed_file(image.filename):
                image_url = upload_image(image, new_item.item_id)
                product_image = ProductImage(item_id=new_item.item_id, image_url=image_url, is_main=True)
                db.session.add(product_image)
            else:
                flash('Invalid image file. Allowed file types are: png, jpg, jpeg, gif.', 'danger')
                return redirect(url_for('admin.add_item'))

        db.session.commit()

        flash('Item added successfully', 'success')
        return redirect(url_for('admin.manage_items'))
    
    categories = Category.query.all()
    tags = Tag.query.all()
    return render_template('admin/add_item.html', categories=categories, tags=tags)

@admin_bp.route('/admin/items/<int:item_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_item(item_id):
    item = Item.query.get_or_404(item_id)
    tags = Tag.query.all()

    if request.method == 'POST':
        item.item_name = request.form['item_name']
        item.item_description = request.form['item_description']
        item.item_price = request.form['item_price']
        item.category_id = request.form['category_id']

        # Remove existing item tags
        ItemTag.query.filter_by(item_id=item.item_id).delete()

        # Add selected tags
        selected_tag_ids = request.form.getlist('tags')
        for tag_id in selected_tag_ids:
            item_tag = ItemTag(item_id=item.item_id, tag_id=tag_id)
            db.session.add(item_tag)

        if 'image' in request.files:
            image = request.files['image']
            if image and allowed_file(image.filename):
                # Delete existing main image from the file system
                main_image = ProductImage.query.filter_by(item_id=item.item_id, is_main=True).first()
                if main_image:
                    delete_image(main_image.image_url)
                
                # Upload new main image
                image_url = upload_image(image, item.item_id)
                
                # Remove existing main image from the database
                ProductImage.query.filter_by(item_id=item.item_id, is_main=True).delete()
                
                # Add new main image to the database
                product_image = ProductImage(item_id=item.item_id, image_url=image_url, is_main=True)
                db.session.add(product_image)
            else:
                flash('Invalid image file. Allowed file types are: png, jpg, jpeg, gif.', 'danger')
                return redirect(url_for('admin.edit_item', item_id=item_id))
        
        db.session.commit()
        flash('Item updated successfully', 'success')
        return redirect(url_for('admin.manage_items'))
    
    categories = Category.query.all()
    item_tags = [tag.tag_id for tag in item.tags]
    return render_template('admin/edit_item.html', item=item, categories=categories, tags=tags, item_tags=item_tags)

@admin_bp.route('/admin/items/<int:item_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)

    # Delete associated images from the file system and the database
    for image in item.images:
        delete_image(image.image_url)  # Remove the image from the file system
        db.session.delete(image)  # Explicitly delete the image from the database
        reset_auto_increment(db, 'product_image', 'image_id')

    # Delete the item from the database
    db.session.delete(item)
    db.session.commit()

    flash('Item deleted successfully', 'success')
    return redirect(url_for('admin.manage_items'))

# tags

@admin_bp.route('/admin/tags', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_tags():
    if request.method == 'POST':
        tag_name = request.form['tag_name']
        new_tag = Tag(tag_name=tag_name)
        db.session.add(new_tag)
        db.session.commit()
        return redirect(url_for('admin.manage_tags'))

    tags = Tag.query.all()
    return render_template('admin/manage_tags.html', tags=tags)

@admin_bp.route('/admin/tags/<int:tag_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_tag(tag_id):
    tag = Tag.query.get_or_404(tag_id)
    
    # Check if the tag is used by any items
    if tag.items:
        item_count = len(tag.items)
        flash(f"Cannot delete the tag. It is used by {item_count} item(s).", 'danger')
    else:
        db.session.delete(tag)
        db.session.commit()
        reset_auto_increment(db, 'tags', 'tag_id')
        flash('Tag deleted successfully', 'success')
    
    return redirect(url_for('admin.manage_tags'))

# user management

@admin_bp.route('/admin/users')
@login_required
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('admin/manage_users.html', users=users)

@admin_bp.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.username = request.form['username']
        user.first_name = request.form['first_name']
        user.last_name = request.form['last_name']
        user.user_email = request.form['email']
        user.is_active = 'is_active' in request.form
        db.session.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('admin.manage_users'))
    
    return render_template('admin/edit_user.html', user=user)

@admin_bp.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    reset_auto_increment(db, 'users', 'user_id')
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin.manage_users'))




# User Routes
@user_bp.route('/user/register', methods=['GET', 'POST'])
def user_register():
    if request.method == 'POST':
        username = request.form['username']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        password_hash = generate_password_hash(password)

        if User.query.filter((User.username == username) | (User.user_email == email)).first():
            flash('Username or email already exists!', 'danger')
            return redirect(url_for('user.user_register'))

        new_user = User(username=username, first_name=first_name, last_name=last_name, user_email=email, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()

        flash('User registered successfully!', 'success')
        return redirect(url_for('user.user_login'))

    return render_template('user/user_register.html')

@user_bp.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.verify_password(password):
            login_user(user)
            # Set user type to user in the session
            session['user_type'] = 'user'
            flash('Login successful!', 'success')
            return redirect(url_for('user.user_dashboard'))

        flash('Invalid username or password', 'danger')

    return render_template('user/user_login.html')

@user_bp.route('/user/logout')
@login_required
def user_logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index.index'))

# user dashboard routes

@user_bp.route('/user/dashboard')
@login_required
def user_dashboard():
    addresses = Address.query.filter_by(user_id=current_user.user_id).all()
    return render_template('user/user_dashboard.html', user=current_user, addresses=addresses)

# Profile Management
@user_bp.route('/user/profile', methods=['GET', 'POST'])
@login_required
def user_profile():
    if request.method == 'POST':
        current_user.first_name = request.form['first_name']
        current_user.last_name = request.form['last_name']
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('user.user_profile'))
    return render_template('user/user_profile.html', user=current_user)

# Change Password
@user_bp.route('/user/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not check_password_hash(current_user.password_hash, current_password):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('user.change_password'))

        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('user.change_password'))

        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        flash('Password changed successfully!', 'success')
        return redirect(url_for('user.user_dashboard'))

    return render_template('user/change_password.html')

# Add Address

# Get a list of all countries from pycountry
COUNTRIES = [country.name for country in pycountry.countries]

# Default country and Iraqi governorates
DEFAULT_COUNTRY = "Iraq"
IRAQ_GOVERNORATES = [
    "Baghdad", "Basra", "Nineveh", "Kirkuk", "Erbil", "Sulaymaniyah", "Duhok",
    "Anbar", "Babylon", "Dhi Qar", "Karbala", "Najaf", "Maysan", "Wasit",
    "Qadisiyah", "Muthanna", "Salah ad-Din", "Diyala"
]

# Add Address
@user_bp.route('/user/address/add', methods=['GET', 'POST'])
@login_required
def add_address():
    if request.method == 'POST':
        address_line = request.form['address_line']
        city = request.form['city']
        country = request.form['country']
        postal_code = request.form['postal_code']
        phone_number = request.form['phone_number'].strip()  # Remove spaces
        governerate = request.form.get('governerate')
        is_default = 'is_default' in request.form

        # Debugging: Log the phone number input
        print(f"DEBUG: Phone Number Input: '{phone_number}'")

        # Ensure phone number contains only digits and has a length of 11
        if not phone_number.isdigit() or len(phone_number) != 11:
            flash("Phone number must contain exactly 11 numeric digits.", "danger")
            return render_template('user/add_address.html', countries=COUNTRIES, governorates=IRAQ_GOVERNORATES, selected_country=country)

        # Validate phone number for Iraq
        if country == "Iraq":
            iraq_phone_pattern = r"^07\d{9}$"  # Matches exactly 07XXXXXXXXX (11 digits)
            if not re.match(iraq_phone_pattern, phone_number):
                flash("Invalid phone number format for Iraq. Use format: 07XXXXXXXXX (11 digits).", "danger")
                return render_template('user/add_address.html', countries=COUNTRIES, governorates=IRAQ_GOVERNORATES, selected_country=country)

        # Handle governerate for Iraq
        if country == "Iraq" and not governerate:
            flash("Governorate is required for Iraq.", "danger")
            return render_template('user/add_address.html', countries=COUNTRIES, governorates=IRAQ_GOVERNORATES, selected_country=country)

        # Set governerate to None for non-Iraq countries
        if country != "Iraq":
            governerate = None

        # Automatically set the first address as default
        if not Address.query.filter_by(user_id=current_user.user_id).count():
            is_default = True

        # Unset default for other addresses if this is set as default
        if is_default:
            Address.query.filter_by(user_id=current_user.user_id, is_default=True).update({'is_default': False})

        new_address = Address(
            user_id=current_user.user_id,
            address_line=address_line,
            city=city,
            governerate=governerate,
            country=country,
            postal_code=postal_code,
            phone_number=phone_number,
            is_default=is_default
        )

        try:
            db.session.add(new_address)
            db.session.commit()
            flash("Address added successfully!", "success")
            return redirect(url_for('user.user_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred: {str(e)}", "danger")
            return redirect(url_for('user.add_address'))

    # Default to Iraq for new addresses
    return render_template('user/add_address.html', countries=COUNTRIES, governorates=IRAQ_GOVERNORATES, selected_country="Iraq")

# Edit Address
@user_bp.route('/user/address/<int:address_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_address(address_id):
    address = Address.query.get_or_404(address_id)

    # Ensure the user owns the address
    if address.user_id != current_user.user_id:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('user.user_dashboard'))

    if request.method == 'POST':
        address_line = request.form['address_line']
        city = request.form['city']
        country = request.form['country']
        postal_code = request.form['postal_code']
        phone_number = request.form['phone_number'].strip()  # Remove spaces
        governerate = request.form.get('governerate')
        is_default = 'is_default' in request.form

        # Debugging: Log the phone number input
        print(f"DEBUG: Phone Number Input: '{phone_number}'")

        # Ensure phone number contains only digits and has a length of 11
        if not phone_number.isdigit() or len(phone_number) != 11:
            flash("Phone number must contain exactly 11 numeric digits.", "danger")
            return render_template('user/edit_address.html', address=address, countries=COUNTRIES, governorates=IRAQ_GOVERNORATES, selected_country=country)

        # Validate phone number for Iraq
        if country == "Iraq":
            iraq_phone_pattern = r"^07\d{9}$"  # Matches exactly 07XXXXXXXXX (11 digits)
            if not re.match(iraq_phone_pattern, phone_number):
                flash("Invalid phone number format for Iraq. Use format: 07XXXXXXXXX (11 digits).", "danger")
                return render_template('user/edit_address.html', address=address, countries=COUNTRIES, governorates=IRAQ_GOVERNORATES, selected_country=country)

        # Handle governerate for Iraq
        if country == "Iraq" and not governerate:
            flash("Governorate is required for Iraq.", "danger")
            return render_template('user/edit_address.html', address=address, countries=COUNTRIES, governorates=IRAQ_GOVERNORATES, selected_country=country)

        # Set governerate to None for non-Iraq countries
        if country != "Iraq":
            governerate = None

        # Unset default for other addresses if this is set as default
        if is_default:
            Address.query.filter_by(user_id=current_user.user_id, is_default=True).update({'is_default': False})

        # Update address fields
        address.address_line = address_line
        address.city = city
        address.governerate = governerate
        address.country = country
        address.postal_code = postal_code
        address.phone_number = phone_number
        address.is_default = is_default

        try:
            db.session.commit()
            flash("Address updated successfully!", "success")
            return redirect(url_for('user.user_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred: {str(e)}", "danger")
            return redirect(url_for('user.edit_address', address_id=address_id))

    return render_template('user/edit_address.html', address=address, countries=COUNTRIES, governorates=IRAQ_GOVERNORATES, selected_country=address.country)

# Set Default Address
@user_bp.route('/user/address/<int:address_id>/set-default', methods=['POST'])
@login_required
def set_default_address(address_id):
    address = Address.query.get_or_404(address_id)

    if address.user_id != current_user.user_id:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('user.user_dashboard'))

    # Unset other default addresses
    Address.query.filter_by(user_id=current_user.user_id, is_default=True).update({'is_default': False})

    # Set the selected address as default
    address.is_default = True
    db.session.commit()

    flash('Default address updated successfully!', 'success')
    return redirect(url_for('user.user_dashboard'))

@user_bp.route('/user/address/<int:address_id>/delete', methods=['POST'])
@login_required
def delete_address(address_id):
    address = Address.query.get_or_404(address_id)

    # Ensure the user owns the address
    if address.user_id != current_user.user_id:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('user.user_dashboard'))

    # Prevent deletion of the default address
    if address.is_default:
        flash("Default address cannot be deleted. Please set another address as default first.", "danger")
        return redirect(url_for('user.user_dashboard'))

    try:
        db.session.delete(address)
        db.session.commit()
        flash("Address deleted successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"An error occurred: {str(e)}", "danger")

    return redirect(url_for('user.user_dashboard'))

# user payments

stripe.api_key = "sk_test_51QhcQwGK7HgCufdXVD0auQv4NGn8qm9TRWXRYlVoPkrvzzoI7WVmE9SYsIMH0zCn6fov7hlyvs0dp8Ra7kv4TC1r00HXsSH5ap" # stripe test secret key

@user_bp.route('/user/payments')
@login_required
def user_payments():
    payment_methods = PaymentMethod.query.filter_by(user_id=current_user.user_id).all()
    return render_template('user/user_payments.html', payment_methods=payment_methods)

@user_bp.route('/user/payments/add', methods=['GET', 'POST'])
@login_required
def add_payment_method():
    if request.method == 'POST':
        payment_method_id = request.form.get('payment_method_id')

        try:
            # Retrieve the PaymentMethod from Stripe
            payment_method = stripe.PaymentMethod.retrieve(payment_method_id)

            # Extract card details
            card = payment_method.card
            issuer = card.brand.title()  # e.g., "Visa"
            last_four_digits = card.last4
            expiry_month = card.exp_month
            expiry_year = card.exp_year

            # Save the payment method in the database
            new_payment = PaymentMethod(
                user_id=current_user.user_id,
                issuer=issuer,
                last_four_digits=last_four_digits,
                expiry_month=expiry_month,
                expiry_year=expiry_year,
                stripe_payment_method_id=payment_method_id
            )
            db.session.add(new_payment)
            db.session.commit()

            flash("Payment method added successfully!", "success")
            return redirect(url_for('user.user_payments'))

        except stripe.error.StripeError as e:
            db.session.rollback()  # Reset the session after failed transaction
            flash(f"Error adding payment method: {e.user_message}", "danger")
            return redirect(url_for('user.add_payment_method'))

        except Exception as e:
            db.session.rollback()  # Reset the session after failed transaction
            flash(f"An error occurred: {str(e)}", "danger")
            return redirect(url_for('user.add_payment_method'))

    return render_template('user/add_payment_method.html')

@user_bp.route('/user/payments/<int:payment_id>/delete', methods=['POST'])
@login_required
def delete_payment_method(payment_id):
    payment = PaymentMethod.query.get_or_404(payment_id)

    if payment.user_id != current_user.user_id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('user.user_payments'))

    try:
        db.session.delete(payment)
        db.session.commit()
        reset_auto_increment(db, 'payment_methods', 'payment_id')
        flash("Payment method deleted successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"An error occurred: {str(e)}", "danger")

    return redirect(url_for('user.user_payments'))

# Item Routes
@item_bp.route('/items')
def item_list():
    items = Item.query.options(joinedload(Item.images)).all()
    return render_template('item_list.html', items=items)

@item_bp.route('/item/<int:item_id>')
def item_detail(item_id):
    item = Item.query.options(joinedload(Item.images)).get_or_404(item_id)
    return render_template('item_detail.html', item=item)

@item_bp.route('/items/search')
def search_items():
    query = request.args.get('q')
    category_id = request.args.get('category')
    tag_id = request.args.get('tag')
    
    items = Item.query.options(joinedload(Item.images))
    
    if query:
        items = items.filter(Item.item_name.ilike(f'%{query}%'))
    
    if category_id:
        items = items.filter(Item.category_id == category_id)
    
    if tag_id:
        items = items.join(Item.tags).filter(Tag.tag_id == tag_id)
    
    items = items.all()
    
    return render_template('search_results.html', items=items, query=query)


# Cart Routes
@cart_bp.route('/cart')
@login_required
def cart():
    cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
    return render_template('cart.html', cart=cart)

@cart_bp.route('/cart/add/<int:item_id>', methods=['POST'])
@login_required
def add_to_cart(item_id):
    item = Item.query.get_or_404(item_id)
    cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
    if not cart:
        cart = ShoppingCart(user_id=current_user.user_id)
        db.session.add(cart)
        db.session.commit()

    cart_item = CartItem(cart_id=cart.cart_id, item_id=item.item_id, quantity=1)
    db.session.add(cart_item)
    db.session.commit()

    flash('Item added to cart!', 'success')
    return redirect(url_for('item.item_detail', item_id=item_id))

# Order Routes
@order_bp.route('/create-order', methods=['POST'])
@login_required
def create_order():
    cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
    if not cart or not cart.items:
        flash('Your cart is empty.', 'danger')
        return redirect(url_for('cart.cart'))
    
    total_amount = sum(item.item.item_price * item.quantity for item in cart.items)
    
    new_order = Order(user_id=current_user.user_id, total_amount=total_amount)
    db.session.add(new_order)
    db.session.commit()

    for cart_item in cart.items:
        order_item = OrderItem(order_id=new_order.order_id, item_id=cart_item.item_id, quantity=cart_item.quantity, price=cart_item.item.item_price)
        db.session.add(order_item)
        db.session.delete(cart_item)

    db.session.commit()

    flash('Order placed successfully!', 'success')
    return redirect(url_for('order.order_list'))

@order_bp.route('/orders')
@login_required
def order_list():
    orders = Order.query.filter_by(user_id=current_user.user_id).all()
    return render_template('order_list.html', orders=orders)
