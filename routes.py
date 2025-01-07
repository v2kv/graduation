from flask import Blueprint, request, render_template, flash, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user
from db import db
from models import Admin, User, Item, ShoppingCart, CartItem, Order
from werkzeug.security import generate_password_hash, check_password_hash

# Blueprints
index_bp = Blueprint('index', __name__)
admin_bp = Blueprint('admin', __name__)
user_bp = Blueprint('user', __name__)
item_bp = Blueprint('item', __name__)
cart_bp = Blueprint('cart', __name__)
order_bp = Blueprint('order', __name__)

@index_bp.route('/')
def index():
    return render_template('index.html')

# Admin Routes
@admin_bp.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        password_hash = generate_password_hash(password)

        if Admin.query.filter((Admin.username == username) | (Admin.email == email)).first():
            flash('Username or email already exists!', 'danger')
            return redirect(url_for('admin.admin_register'))

        new_admin = Admin(username=username, email=email, password_hash=password_hash)
        db.session.add(new_admin)
        db.session.commit()

        flash('Admin registered successfully!', 'success')
        return redirect(url_for('admin.admin_login'))

    return render_template('admin_register.html')

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