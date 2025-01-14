from flask import Blueprint, request, render_template, flash, redirect, url_for, current_app
from flask_login import login_user, logout_user, login_required, current_user
from db import db
from models import Admin, User, Item, ShoppingCart, CartItem, Order, Category, OrderItem, Tag, ItemTag
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy.orm import joinedload

# Blueprints
index_bp = Blueprint('index', __name__)
admin_bp = Blueprint('admin', __name__)
user_bp = Blueprint('user', __name__)
item_bp = Blueprint('item', __name__)
cart_bp = Blueprint('cart', __name__)
order_bp = Blueprint('order', __name__)

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
    return render_template('index.html')

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
        tags = request.form['tags'].split(',')
        
        new_item = Item(item_name=item_name, item_description=item_description, item_price=item_price, category_id=category_id)
        db.session.add(new_item)
        db.session.commit()

        for tag_name in tags:
            tag_name = tag_name.strip()
            if tag_name:
                tag = Tag.query.filter_by(tag_name=tag_name).first()
                if not tag:
                    tag = Tag(tag_name=tag_name)
                    db.session.add(tag)
                    db.session.commit()
                item_tag = ItemTag(item=new_item, tag=tag)
                db.session.add(item_tag)

        db.session.commit()

        flash('Item added successfully', 'success')
        return redirect(url_for('admin.manage_items'))
    
    categories = Category.query.all()
    return render_template('admin/add_item.html', categories=categories)

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

        item.tags = []
        selected_tag_ids = request.form.getlist('tags')
        for tag_id in selected_tag_ids:
            tag = Tag.query.get(tag_id)
            item.tags.append(tag)
        
        db.session.commit()
        flash('Item updated successfully', 'success')
        return redirect(url_for('admin.manage_items'))
    
    categories = Category.query.all()
    return render_template('admin/edit_item.html', item=item, categories=categories)


@admin_bp.route('/admin/items/<int:item_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    flash('Item deleted successfully', 'success')
    return redirect(url_for('admin.manage_items'))

# tag creation

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

@user_bp.route('/user/dashboard')
@login_required
def user_dashboard():
    return render_template('user/user_dashboard.html')

# Item Routes

@item_bp.route('/items')
def item_list():
    items = Item.query.all()
    return render_template('item_list.html', items=items)


@item_bp.route('/item/<int:item_id>')
def item_detail(item_id):
    item = Item.query.get_or_404(item_id)
    return render_template('item_detail.html', item=item)

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

@order_bp.route('/order/<int:order_id>')
@login_required
def order_detail(order_id):
    order = Order.query.get_or_404(order_id)
    return render_template('order_detail.html', order=order)

