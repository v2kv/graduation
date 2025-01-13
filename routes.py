from flask import Blueprint, request, render_template, flash, redirect, url_for, current_app
from flask_login import login_user, logout_user, login_required, current_user
from db import db
from models import Admin, User, Item, ShoppingCart, CartItem, Order, Category
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

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

    return render_template('admin_register.html', secret_token=secret_token)

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

    return render_template('admin_login.html')

@admin_bp.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index.index'))

@admin_bp.route('/admin/dashboard')
@login_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

# admin functionalities

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

    return render_template('user_register.html')


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

    return render_template('user_login.html')

@user_bp.route('/user/logout')
@login_required
def user_logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index.index'))

@user_bp.route('/user/dashboard')
@login_required
def user_dashboard():
    return render_template('user_dashboard.html')

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

