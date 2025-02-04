import os
from flask import Blueprint, session, request, render_template, flash, redirect, url_for, current_app, jsonify
from flask_login import login_user, logout_user, login_required, current_user
import pycountry # list of all countries for address
import re # check phone number format
import stripe # simulate payments
from stripe.error import StripeError
from db import db
from models import Admin, User, Item, ShoppingCart, CartItem, Wishlist, WishlistItem, Order, Category, Tag, ItemTag, ProductImage, Address, PaymentMethod, Message
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
wishlist_bp = Blueprint('wishlist', __name__)
order_bp = Blueprint('order', __name__)

# admin required decorator for routes only accessible by admins

def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You do not have permission to access this page.', 'warning')
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    return decorated_view

def get_all_subcategories(category):
    """Helper function to recursively get IDs of all subcategories of a given category."""
    subcategories = []
    def gather_subcategories(cat):
        for sub in cat.subcategories:
            subcategories.append(sub)
            gather_subcategories(sub)
    gather_subcategories(category)
    return subcategories

@index_bp.route('/')
def index():
    categories = Category.query.all()  # Fetch all categories for filtering
    items = Item.query.options(joinedload(Item.images)).all()  # Fetch all items by default

    # Fetch counts for badges
    cart_count = 0
    wishlist_count = 0
    orders_count = 0
    unread_messages_count = 0
    if current_user.is_authenticated:
        cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
        cart_count = sum(item.quantity for item in cart.items) if cart else 0

        wishlist = Wishlist.query.filter_by(user_id=current_user.user_id).first()
        wishlist_count = len(wishlist.items) if wishlist else 0

        # Count the total number of orders
        orders_count = Order.query.filter_by(user_id=current_user.user_id).count()

        unread_messages_count = Message.query.filter_by(user_id=current_user.user_id, is_read=False).count()

    return render_template(
        'index.html',
        items=items,
        categories=categories,
        cart_count=cart_count,
        wishlist_count=wishlist_count,
        orders_count=orders_count,
        unread_messages_count=unread_messages_count
    )


# Inject counts into the global context to make them available in all templates
@index_bp.app_context_processor
def inject_counts():
    if current_user.is_authenticated:
        cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
        wishlist = Wishlist.query.filter_by(user_id=current_user.user_id).first()
        unread_messages_count = Message.query.filter_by(user_id=current_user.user_id, is_read=False).count()
        orders_count = Order.query.filter_by(user_id=current_user.user_id).count()

        return {
            'cart_count': sum(item.quantity for item in cart.items) if cart else 0,
            'wishlist_count': len(wishlist.items) if wishlist else 0,
            'orders_count': orders_count,
            'unread_messages_count': unread_messages_count
        }
    return {
        'cart_count': 0,
        'wishlist_count': 0,
        'orders_count': 0,
        'unread_messages_count': 0
    }


# API to get the counts dynamically
@index_bp.route('/api/counters')
@login_required
def get_counters():
    cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
    wishlist = Wishlist.query.filter_by(user_id=current_user.user_id).first()
    unread_messages_count = Message.query.filter_by(user_id=current_user.user_id, is_read=False).count()
    orders_count = Order.query.filter_by(user_id=current_user.user_id).count()

    return jsonify({
        'cart_count': sum(item.quantity for item in cart.items) if cart else 0,
        'wishlist_count': len(wishlist.items) if wishlist else 0,
        'orders_count': orders_count,
        'unread_messages_count': unread_messages_count
    })

@index_bp.route('/filter', methods=['POST'])
def filter_items():
    """Handle the category filtering via AJAX."""
    category_id = request.json.get('category_id')
    if not category_id:
        # If no category is selected, return all items
        items = Item.query.options(joinedload(Item.images)).all()
    else:
        selected_category = Category.query.get(category_id)
        if selected_category:
            # Gather all subcategories of the selected category
            all_subcategories = get_all_subcategories(selected_category)
            category_ids = [selected_category.category_id] + [sub.category_id for sub in all_subcategories]
            # Filter items belonging to the selected category or its subcategories
            items = Item.query.filter(Item.category_id.in_(category_ids)).options(joinedload(Item.images)).all()
        else:
            items = []  # No items if the category is invalid

    # Return the filtered items as JSON
    return jsonify([
        {
            'id': item.item_id,
            'name': item.item_name,
            'price': str(item.item_price),
            'description': item.item_description,
            'image_url': item.images[0].image_url if item.images else None
        }
        for item in items
    ])

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
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')

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
    # Get only parent categories (those without parents)
    top_level_categories = Category.query.filter_by(parent_category_id=None).all()
    return render_template('admin/manage_categories.html', categories=top_level_categories)

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
def add_item():
    if request.method == 'POST':
        try:
            # Get item details
            item_name = request.form['item_name']
            item_description = request.form['item_description']
            item_price = request.form['item_price']
            category_id = request.form['category_id']
            tag_ids = request.form.getlist('tags')

            # Create new item
            new_item = Item(
                item_name=item_name,
                item_description=item_description,
                item_price=item_price,
                category_id=category_id
            )
            db.session.add(new_item)
            db.session.commit()

            # Add tags
            for tag_id in tag_ids:
                item_tag = ItemTag(item_id=new_item.item_id, tag_id=tag_id)
                db.session.add(item_tag)

            # Handle image upload
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
            flash('Item added successfully!', 'success')
            return redirect(url_for('admin.manage_items'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error: {str(e)}", "danger")
            return redirect(url_for('admin.add_item'))

    categories = Category.query.all()
    tags = Tag.query.all()
    return render_template('admin/add_item.html', categories=categories, tags=tags)

@admin_bp.route('/admin/items/<int:item_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    item = Item.query.get_or_404(item_id)
    tags = Tag.query.all()

    if request.method == 'POST':
        try:
            # Update item details
            item.item_name = request.form['item_name']
            item.item_description = request.form['item_description']
            item.item_price = request.form['item_price']
            item.category_id = request.form['category_id']

            # Update tags
            ItemTag.query.filter_by(item_id=item.item_id).delete()
            selected_tag_ids = request.form.getlist('tags')
            for tag_id in selected_tag_ids:
                item_tag = ItemTag(item_id=item.item_id, tag_id=tag_id)
                db.session.add(item_tag)

            # Handle image upload
            if 'image' in request.files and request.files['image'].filename != '':
                image = request.files['image']
                if image and allowed_file(image.filename):
                    # Delete existing main image
                    main_image = ProductImage.query.filter_by(item_id=item.item_id, is_main=True).first()
                    if main_image:
                        delete_image(main_image.image_url)
                        db.session.delete(main_image)

                    # Upload new image
                    image_url = upload_image(image, item.item_id)
                    product_image = ProductImage(item_id=item.item_id, image_url=image_url, is_main=True)
                    db.session.add(product_image)
                else:
                    flash('Invalid image file. Allowed file types are: png, jpg, jpeg, gif.', 'danger')
                    return redirect(url_for('admin.edit_item', item_id=item_id))

            db.session.commit()
            flash('Item updated successfully!', 'success')
            return redirect(url_for('admin.manage_items'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error: {str(e)}", "danger")
            return redirect(url_for('admin.edit_item', item_id=item_id))

    categories = Category.query.all()
    item_tags = [tag.tag_id for tag in item.tags]
    main_image = ProductImage.query.filter_by(item_id=item.item_id, is_main=True).first()
    return render_template('admin/edit_item.html', item=item, categories=categories, tags=tags, item_tags=item_tags, main_image=main_image)

@admin_bp.route('/admin/items/<int:item_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)

    # Delete associated images from the file system and the database
    for image in item.images:
        delete_image(image.image_url)  # Remove the image from the file system
        db.session.delete(image)  # Explicitly delete the image from the database
        reset_auto_increment(db, 'product_images', 'image_id')

    # Delete the item from the database
    db.session.delete(item)
    db.session.commit()
    reset_auto_increment(db, 'items', 'item_id')

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

# order management

@admin_bp.route('/admin/orders')
@login_required
@admin_required
def manage_orders():
    orders = Order.query.all()
    return render_template('admin/manage_orders.html', orders=orders)

@admin_bp.route('/admin/orders/<int:order_id>/update', methods=['POST'])
@login_required
@admin_required
def update_order_status(order_id):
    order = Order.query.get_or_404(order_id)
    new_status = request.form.get('status')
    
    valid_statuses = ['sent', 'delivered', 'cancelled']
    if new_status not in valid_statuses:
        flash('Invalid status.', 'danger')
        return redirect(url_for('admin.manage_orders'))
    
    order.order_status = new_status
    message = Message(
        user_id=order.user_id,
        order_id=order.order_id,
        content=f"Order status updated to {new_status.replace('_', ' ').title()}"
    )
    db.session.add(message)
    db.session.commit()
    flash('Order status updated.', 'success')
    return redirect(url_for('admin.manage_orders'))

@admin_bp.route('/admin/orders/<int:order_id>/process-refund', methods=['POST'])
@login_required
@admin_required
def process_refund(order_id):
    order = Order.query.get_or_404(order_id)
    action = request.form.get('action')
    denial_reason = request.form.get('denial_reason')
    
    if action == 'approve':
        try:
            stripe.api_key = current_app.config['STRIPE_SECRET_KEY']
            refund = stripe.Refund.create(
                payment_intent=order.stripe_payment_intent,
                reason='requested_by_customer'
            )
            
            order.order_status = 'refunded'
            order.refund_status = 'approved'
            message = Message(
                user_id=order.user_id,
                order_id=order.order_id,
                content=f"Your refund request for Order #{order.order_id} has been approved and processed."
            )
        except StripeError as e:
            flash(f'Refund failed: {e.user_message}', 'danger')
            return redirect(url_for('admin.manage_orders'))
    elif action == 'deny':
        if not denial_reason:
            flash('Please provide a reason for denying the refund.', 'danger')
            return redirect(url_for('admin.manage_orders'))
        
        order.refund_status = 'denied'
        order.refund_denial_reason = denial_reason
        message = Message(
            user_id=order.user_id,
            order_id=order.order_id,
            content=f"Your refund request for Order #{order.order_id} has been denied. Reason: {denial_reason}"
        )
    
    db.session.add(message)
    db.session.commit()
    flash('Refund request processed.', 'success')
    return redirect(url_for('admin.manage_orders'))

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
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')

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

        current_user.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
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
        reset_auto_increment(db, 'addresses', 'address_id')
        flash("Address deleted successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"An error occurred: {str(e)}", "danger")

    return redirect(url_for('user.user_dashboard'))

# user payments

@user_bp.route('/user/payments')
@login_required
def user_payments():
    payment_methods = PaymentMethod.query.filter_by(user_id=current_user.user_id).all()
    return render_template('user/user_payments.html', payment_methods=payment_methods)


@user_bp.route('/user/payments/add', methods=['GET', 'POST'])
@login_required
def add_payment_method():
    stripe.api_key = current_app.config['STRIPE_SECRET_KEY']
    if request.method == 'POST':
        payment_method_id = request.form.get('payment_method_id')

        # Retrieve the payment method from Stripe
        payment_method = stripe.PaymentMethod.retrieve(payment_method_id)

        # Create a Stripe Customer if the user doesn't have one
        if not current_user.stripe_customer_id:
            customer = stripe.Customer.create(email=current_user.user_email)
            current_user.stripe_customer_id = customer.id
            db.session.commit()

        # Attach the payment method to the customer
        stripe.PaymentMethod.attach(
            payment_method_id,
            customer=current_user.stripe_customer_id
        )

        # Set this payment method as the default for the customer
        stripe.Customer.modify(
            current_user.stripe_customer_id,
            invoice_settings={
                'default_payment_method': payment_method_id
            }
        )

        # Save the payment method in the database
        new_payment = PaymentMethod(
            user_id=current_user.user_id,
            issuer=payment_method.card.brand.title(),
            last_four_digits=payment_method.card.last4,
            expiry_month=payment_method.card.exp_month,
            expiry_year=payment_method.card.exp_year,
            stripe_payment_method_id=payment_method_id,
            is_default=not PaymentMethod.query.filter_by(user_id=current_user.user_id).count()
        )
        db.session.add(new_payment)
        db.session.commit()

        flash("Payment method added successfully!", "success")
        return redirect(url_for('user.user_payments'))
    return render_template('user/add_payment_method.html')

@user_bp.route('/user/payments/<int:payment_id>/set-default', methods=['POST'])
@login_required
def set_default_payment_method(payment_id):
    payment = PaymentMethod.query.get_or_404(payment_id)

    # Ensure the user owns the payment method
    if payment.user_id != current_user.user_id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('user.user_payments'))

    try:
        # Unset the current default payment method
        PaymentMethod.query.filter_by(user_id=current_user.user_id, is_default=True).update({'is_default': False})

        # Set the selected payment method as the default
        payment.is_default = True
        db.session.commit()

        # Update Stripe customer's default payment method
        stripe.Customer.modify(
            current_user.stripe_customer_id,
            invoice_settings={
                'default_payment_method': payment.stripe_payment_method_id
            }
        )

        flash("Default payment method updated successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"An error occurred: {str(e)}", "danger")

    return redirect(url_for('user.user_payments'))

@user_bp.route('/user/payments/<int:payment_id>/delete', methods=['POST'])
@login_required
def delete_payment_method(payment_id):
    payment = PaymentMethod.query.get_or_404(payment_id)

    # Ensure the user owns the payment method
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


# User Messages
@user_bp.route('/user/messages')
@login_required
def user_messages():
    messages = Message.query.filter_by(user_id=current_user.user_id).order_by(Message.created_at.desc()).all()
    return render_template('user/messages.html', messages=messages)

@user_bp.route('/user/messages/<int:message_id>/mark-read', methods=['POST'])
@login_required
def mark_message_read(message_id):
    message = Message.query.get_or_404(message_id)
    if message.user_id != current_user.user_id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('user.user_messages'))
    
    message.is_read = True
    db.session.commit()
    return redirect(url_for('user.user_messages'))

# item routes

@item_bp.route('/items')
def item_list():
    items = Item.query.options(joinedload(Item.images)).all()
    categories = Category.query.all()  # Add categories for filtering
    return render_template('item_list.html', items=items, categories=categories)

@item_bp.route('/item/<int:item_id>')
def item_detail(item_id):
    item = Item.query.options(joinedload(Item.images)).get_or_404(item_id)
    return render_template('item_detail.html', item=item)

# Cart Routes
@cart_bp.route('/cart')
@login_required
def view_cart():
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

    cart_item = CartItem.query.filter_by(cart_id=cart.cart_id, item_id=item_id).first()
    if cart_item:
        cart_item.quantity += 1
    else:
        cart_item = CartItem(cart_id=cart.cart_id, item_id=item_id, quantity=1)
        db.session.add(cart_item)

    db.session.commit()
    flash('Item added to cart!', 'success')
    return redirect(url_for('cart.view_cart'))

@cart_bp.route('/cart/update/<int:cart_item_id>', methods=['POST'])
@login_required
def update_cart_item(cart_item_id):
    try:
        cart_item = CartItem.query.get_or_404(cart_item_id)
        if cart_item.cart.user_id != current_user.user_id:
            return jsonify({'error': 'Unauthorized'}), 403

        data = request.get_json()
        action = data.get('action')

        if action == 'increase':
            cart_item.quantity += 1
        elif action == 'decrease' and cart_item.quantity > 1:
            cart_item.quantity -= 1
        else:
            return jsonify({'error': 'Invalid action'}), 400

        db.session.commit()
        return jsonify({
            'message': 'Cart updated successfully',
            'quantity': cart_item.quantity,
            'total_price': float(cart_item.total_price)
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@cart_bp.route('/cart/remove/<int:cart_item_id>', methods=['POST'])
@login_required
def remove_from_cart(cart_item_id):
    cart_item = CartItem.query.get_or_404(cart_item_id)
    if cart_item.cart.user_id != current_user.user_id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('cart.view_cart'))

    db.session.delete(cart_item)
    db.session.commit()
    reset_auto_increment(db, 'cart_items', 'cart_item_id')
    flash('Item removed from cart.', 'success')
    return redirect(url_for('cart.view_cart'))

@cart_bp.route('/cart/move-to-wishlist/<int:cart_item_id>', methods=['POST'])
@login_required
def move_to_wishlist(cart_item_id):
    cart_item = CartItem.query.get_or_404(cart_item_id)

    # Ensure the user owns the cart item
    if cart_item.cart.user_id != current_user.user_id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('cart.view_cart'))

    # Add the item to the wishlist
    wishlist = Wishlist.query.filter_by(user_id=current_user.user_id).first()
    if not wishlist:
        wishlist = Wishlist(user_id=current_user.user_id)
        db.session.add(wishlist)
        db.session.commit()

    wishlist_item = WishlistItem.query.filter_by(wishlist_id=wishlist.wishlist_id, item_id=cart_item.item_id).first()
    if not wishlist_item:
        wishlist_item = WishlistItem(wishlist_id=wishlist.wishlist_id, item_id=cart_item.item_id)
        db.session.add(wishlist_item)

    # Remove the item from the cart
    db.session.delete(cart_item)
    reset_auto_increment(db, 'cart_items', 'cart_item_id')
    db.session.commit()

    flash('Item moved to wishlist!', 'success')
    return redirect(url_for('cart.view_cart'))

# Wishlist Routes
@wishlist_bp.route('/wishlist')
@login_required
def view_wishlist():
    wishlist = Wishlist.query.filter_by(user_id=current_user.user_id).first()
    return render_template('wishlist.html', wishlist=wishlist)


@wishlist_bp.route('/wishlist/add/<int:item_id>', methods=['POST'])
@login_required
def add_to_wishlist(item_id):
    item = Item.query.get_or_404(item_id)
    wishlist = Wishlist.query.filter_by(user_id=current_user.user_id).first()
    if not wishlist:
        wishlist = Wishlist(user_id=current_user.user_id)
        db.session.add(wishlist)
        db.session.commit()

    wishlist_item = WishlistItem.query.filter_by(wishlist_id=wishlist.wishlist_id, item_id=item_id).first()
    if wishlist_item:
        flash('Item is already in your wishlist.', 'warning')
    else:
        wishlist_item = WishlistItem(wishlist_id=wishlist.wishlist_id, item_id=item_id)
        db.session.add(wishlist_item)
        db.session.commit()
        flash('Item added to wishlist!', 'success')

    return redirect(url_for('wishlist.view_wishlist'))


@wishlist_bp.route('/wishlist/remove/<int:wishlist_item_id>', methods=['POST'])
@login_required
def remove_from_wishlist(wishlist_item_id):
    wishlist_item = WishlistItem.query.get_or_404(wishlist_item_id)
    if wishlist_item.wishlist.user_id != current_user.user_id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('wishlist.view_wishlist'))

    db.session.delete(wishlist_item)
    db.session.commit()
    reset_auto_increment(db, 'wishlist_items', 'wishlist_item_id')
    flash('Item removed from wishlist.', 'success')
    return redirect(url_for('wishlist.view_wishlist'))

@wishlist_bp.route('/wishlist/move-to-cart/<int:wishlist_item_id>', methods=['POST'])
@login_required
def move_to_cart(wishlist_item_id):
    wishlist_item = WishlistItem.query.get_or_404(wishlist_item_id)

    # Ensure the user owns the wishlist item
    if wishlist_item.wishlist.user_id != current_user.user_id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('wishlist.view_wishlist'))

    # Add the item to the cart
    cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
    if not cart:
        cart = ShoppingCart(user_id=current_user.user_id)
        db.session.add(cart)
        db.session.commit()

    cart_item = CartItem.query.filter_by(cart_id=cart.cart_id, item_id=wishlist_item.item_id).first()
    if cart_item:
        cart_item.quantity += 1
    else:
        cart_item = CartItem(cart_id=cart.cart_id, item_id=wishlist_item.item_id, quantity=1)
        db.session.add(cart_item)

    # Remove the item from the wishlist
    db.session.delete(wishlist_item)
    db.session.commit()

    flash('Item moved to cart!', 'success')
    return redirect(url_for('wishlist.view_wishlist'))


# Order Routes

@order_bp.route('/orders')
@login_required
def view_orders():
    orders = Order.query.filter_by(user_id=current_user.user_id).all()
    return render_template('order_list.html', orders=orders)

@order_bp.route('/orders/<int:order_id>')
@login_required
def order_detail(order_id):
    order = Order.query.get_or_404(order_id)
    return render_template('order_detail.html', order=order)

@order_bp.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
    if not cart or not cart.items:
        flash('Your cart is empty.', 'danger')
        return redirect(url_for('cart.view_cart'))

    addresses = Address.query.filter_by(user_id=current_user.user_id).all()
    payment_methods = PaymentMethod.query.filter_by(user_id=current_user.user_id).all()

    if request.method == 'POST':
        address_id = request.form.get('address_id')
        payment_method_id = request.form.get('payment_method_id')

        # Validate the address and payment method
        if not address_id or not payment_method_id:
            flash('Please select both an address and a payment method.', 'danger')
            return redirect(url_for('order.checkout'))

        # Store the selected address and payment method in the session
        session['address_id'] = address_id
        session['payment_method_id'] = payment_method_id

        # Redirect to the Stripe Checkout route
        return redirect(url_for('order.stripe_checkout_session'))

    return render_template('checkout.html', cart=cart, addresses=addresses, payment_methods=payment_methods)


@order_bp.route('/stripe_checkout_session', methods=['GET'])
@login_required
def stripe_checkout_session():
    stripe.api_key = current_app.config['STRIPE_SECRET_KEY']
    address_id = session.get('address_id')
    payment_method_id = session.get('payment_method_id')

    try:
        # Validate address and cart
        address = Address.query.get(address_id)
        if not address or address.user_id != current_user.user_id:
            flash('Invalid shipping address', 'danger')
            return redirect(url_for('order.checkout'))

        cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
        if not cart or not cart.items:
            flash('Your cart is empty', 'danger')
            return redirect(url_for('cart.view_cart'))

        total_amount = sum(item.item.item_price * item.quantity for item in cart.items)
        total_cents = int(total_amount * 100)

        # If using existing payment method
        if payment_method_id and payment_method_id != 'new':
            # Fetch the correct Stripe payment method ID from the database
            payment_method = PaymentMethod.query.filter_by(
                payment_id=payment_method_id, 
                user_id=current_user.user_id
            ).first()

            if not payment_method:
                flash('Invalid payment method selected.', 'danger')
                return redirect(url_for('order.checkout'))

            stripe_payment_method_id = payment_method.stripe_payment_method_id 

            # Attach payment method to customer (if not already attached)
            if not payment_method.is_default:
                stripe.PaymentMethod.attach(
                    stripe_payment_method_id,
                    customer=current_user.stripe_customer_id
                )

                # Mark the payment method as default
                payment_method.is_default = True
                db.session.commit()

            # Create Payment Intent
            payment_intent = stripe.PaymentIntent.create(
                amount=total_cents,
                currency='usd',
                customer=current_user.stripe_customer_id,
                payment_method=stripe_payment_method_id,
                confirm=True,
                automatic_payment_methods={
                    'enabled': True,
                    'allow_redirects': 'never' 
                },
                metadata={
                    'address_id': address_id,
                    'user_id': current_user.user_id
                }
            )

            # Redirect on successful payment
            return redirect(url_for('order.stripe_success', payment_intent_id=payment_intent.id))

        # For new payment methods, use Checkout Session
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'unit_amount': total_cents,
                    'product_data': {'name': 'Order Total'},
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=url_for('order.stripe_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('order.stripe_cancel', _external=True),
            customer=current_user.stripe_customer_id or None,
            metadata={
                'address_id': address_id,
                'user_id': current_user.user_id
            }
        )

        return redirect(checkout_session.url, code=303)

    except stripe.error.StripeError as e:
        current_app.logger.error(f"Stripe error: {str(e)}")
        flash(f"Payment error: {e.user_message}", 'danger')
        return redirect(url_for('order.checkout'))
    except Exception as e:
        current_app.logger.error(f"Checkout error: {str(e)}")
        flash("Error processing payment. Please try again.", 'danger')
        return redirect(url_for('order.checkout'))

@order_bp.route('/stripe-success')
@login_required
def stripe_success():
    try:
        payment_intent_id = request.args.get('payment_intent_id')
        session_id = request.args.get('session_id')

        metadata = None

        if payment_intent_id:
            # Retrieve metadata from PaymentIntent
            payment_intent = stripe.PaymentIntent.retrieve(payment_intent_id)
            metadata = payment_intent.metadata
        elif session_id:
            # Retrieve metadata from CheckoutSession
            checkout_session = stripe.checkout.Session.retrieve(session_id)
            metadata = checkout_session.metadata
        else:
            raise ValueError("Missing payment verification ID")

        # Extract address_id and user_id from metadata
        address_id = metadata.get('address_id')
        user_id = metadata.get('user_id')

        if not address_id or int(user_id) != current_user.user_id:
            raise ValueError("Invalid metadata in payment confirmation.")

        # Process order creation
        cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
        if not cart or not cart.items:
            flash('Your cart is empty', 'danger')
            return redirect(url_for('cart.view_cart'))

        total_amount = sum(item.item.item_price * item.quantity for item in cart.items)

        # Save the order in the database
        new_order = Order(
            user_id=current_user.user_id,
            shipping_address_id=address_id,
            total_amount=total_amount,
            order_status='payment_successful, delivery pending',
            stripe_payment_intent=payment_intent_id or checkout_session.payment_intent
        )

        db.session.add(new_order)

        message = Message(
            user_id=current_user.user_id,
            order_id=new_order.order_id,
            content=f"Order has been created successfully. Total amount: ${total_amount}"
        )
        db.session.add(message)

        # Clear the cart
        CartItem.query.filter_by(cart_id=cart.cart_id).delete()
        db.session.commit()

        # Clear session data
        session.pop('address_id', None)
        session.pop('payment_method_id', None)

        flash('Payment successful! Your order has been placed.', 'success')
        return redirect(url_for('order.view_orders'))

    except (StripeError, ValueError, AttributeError) as e:
        db.session.rollback()
        current_app.logger.error(f"Order processing error: {str(e)}")
        flash('Error processing your order. Please contact support.', 'danger')
        return redirect(url_for('order.checkout'))
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Unexpected error: {str(e)}")
        flash('An unexpected error occurred. Please contact support.', 'danger')
        return redirect(url_for('order.checkout'))


@order_bp.route('/stripe-cancel')
@login_required
def stripe_cancel():
    flash('Payment was cancelled.', 'warning')
    return redirect(url_for('order.checkout'))

@order_bp.route('/orders/<int:order_id>/cancel', methods=['POST'])
@login_required
def cancel_order(order_id):
    order = Order.query.get_or_404(order_id)
    
    if order.user_id != current_user.user_id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('order.view_orders'))
    
    if order.order_status not in ['payment_successful, delivery pending', 'pending']:
        flash('This order cannot be canceled.', 'danger')
        return redirect(url_for('order.view_orders'))
    
    try:
        # Create refund in Stripe
        stripe.api_key = current_app.config['STRIPE_SECRET_KEY']
        refund = stripe.Refund.create(
            payment_intent=order.stripe_payment_intent,
            reason='requested_by_customer'
        )
        
        order.order_status = 'cancelled'
        message = Message(
            user_id=current_user.user_id,
            order_id=order.order_id,
            content=f"Order #{order.order_id} has been cancelled and refund processed."
        )
        db.session.add(message)
        db.session.commit()
        flash('Order cancelled and refund processed.', 'success')
    except StripeError as e:
        flash(f'Refund failed: {e.user_message}', 'danger')
    
    return redirect(url_for('order.view_orders'))

@order_bp.route('/orders/<int:order_id>/request-refund', methods=['POST'])
@login_required
def request_refund(order_id):
    order = Order.query.get_or_404(order_id)

    if order.user_id != current_user.user_id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('order.view_orders'))
    
    if order.order_status != 'sent':
        flash('Only orders that have been sent can request refunds.', 'danger')
        return redirect(url_for('order.view_orders'))

    order.refund_requested = True
    db.session.commit()

    flash('Refund request submitted. An admin will review it shortly.', 'success')
    return redirect(url_for('order.view_orders'))