import os
from flask import Blueprint, session, request, render_template, flash, redirect, url_for, current_app, jsonify
from flask_login import login_user, logout_user, login_required, current_user
import re # check phone number and password format using regex
import stripe # simulate payments
from stripe.error import StripeError
from db import db, mail
from models import Admin, User, Item, ShoppingCart, CartItem, Wishlist, WishlistItem, Order, Category, Tag, ItemTag, ProductImage, Address, PaymentMethod, Messages
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy import or_, and_
from sqlalchemy.orm import joinedload
from sqlalchemy.exc import IntegrityError
from db import reset_auto_increment, allowed_file, upload_image, delete_image # functions defined in db.py
from itsdangerous import TimedSerializer as Serializer
from itsdangerous import SignatureExpired, BadSignature
from flask_mail import Message
import requests


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
    categories = Category.query.all()  # Fetch all categories

    # Structure categories into a dictionary grouped by parent ID
    category_tree = {}
    for category in categories:
        parent_id = category.parent_category_id or 0  # Root categories get parent_id = 0
        if parent_id not in category_tree:
            category_tree[parent_id] = []
        category_tree[parent_id].append(category)

    # Fetch items ordered by name (ascending)
    items = Item.query.options(joinedload(Item.images)).order_by(Item.item_name.asc()).all()

    # Fetch counts for badges
    cart_count = 0
    wishlist_count = 0
    orders_count = 0
    unread_messages_count = 0
    if current_user.is_authenticated and current_user.role != "admin":
        cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
        cart_count = sum(item.quantity for item in cart.items) if cart else 0

        wishlist = Wishlist.query.filter_by(user_id=current_user.user_id).first()
        wishlist_count = len(wishlist.items) if wishlist else 0

        orders_count = Order.query.filter_by(user_id=current_user.user_id).filter(
            ~Order.order_status.in_(['delivered', 'cancelled'])
        ).count()

        unread_messages_count = Messages.query.filter_by(user_id=current_user.user_id, is_read=False).count()

    return render_template(
        'index.html',
        items=items,
        category_tree=category_tree,  # Pass structured categories
        cart_count=cart_count,
        wishlist_count=wishlist_count,
        orders_count=orders_count,
        unread_messages_count=unread_messages_count,
        show_footer=True
    )

# Inject counts into the global context to make them available in all templates
@index_bp.app_context_processor
def inject_counts():
    if current_user.is_authenticated and current_user.role != "admin":
        cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
        wishlist = Wishlist.query.filter_by(user_id=current_user.user_id).first()
        
        unread_messages_count = Messages.query.filter_by(user_id=current_user.user_id, is_read=False).count()
        orders_count = Order.query.filter_by(user_id=current_user.user_id).filter(
            ~Order.order_status.in_(['delivered', 'cancelled'])
        ).count()

        return {
            'cart_count': sum(item.quantity for item in cart.items) if cart else 0,
            'wishlist_count': len(wishlist.items) if wishlist else 0,
            'orders_count': orders_count,
            'unread_messages_count': unread_messages_count
        }

    cate=Category.query.count();
    NoOfUsers=User.query.count();
    NoOfItems=Item.query.count();
    NoOfTag=Tag.query.count();
    NoOfOrder=Order.query.count();
    return {
        'cart_count': 0,
        'wishlist_count': 0,
        'orders_count': 0,
        'unread_messages_count': 0,
        'NoOfUsers': NoOfUsers,
        'NoOfItems': NoOfItems,
        'NoOfTag': NoOfTag,
        'NoOfOrder': NoOfOrder,
        'cate':cate
    }

def generate_slug(name):
    """Convert category names into URL-friendly slugs (lowercase, hyphenated)."""
    return re.sub(r'\W+', '-', name.strip().lower()).strip('-')
# API to get the counts dynamically
@index_bp.route('/api/counters')
@login_required
def get_counters():
    if current_user.is_authenticated and current_user.role != "admin":
        cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
        wishlist = Wishlist.query.filter_by(user_id=current_user.user_id).first()
        no_of_users=session.query(User.user_id).count();
        unread_messages_count = Messages.query.filter_by(user_id=current_user.user_id, is_read=False).count()
        orders_count = Order.query.filter_by(user_id=current_user.user_id).filter(
            ~Order.order_status.in_(['delivered', 'cancelled'])
        ).count()

        return jsonify({
            'cart_count': sum(item.quantity for item in cart.items) if cart else 0,
            'wishlist_count': len(wishlist.items) if wishlist else 0,
            'orders_count': orders_count,
            'unread_messages_count': unread_messages_count
        })
    return None
@index_bp.route('/category/<category_slug>')
def filter_by_category(category_slug):
    """Filter items based on category slug."""
    category_slug = category_slug.lower()  # Ensure lowercase comparison
    print(f"Searching for category slug: {category_slug}")  # Debugging

    # ✅ Query all categories and compare slugs
    selected_category = next(
        (c for c in Category.query.all() if generate_slug(c.category_name) == category_slug),
        None
    )

    if not selected_category:
        print("Category not found!")  # Debugging
        return "Category not found", 404

    # ✅ Fetch subcategories
    all_subcategories = get_all_subcategories(selected_category)
    category_ids = [selected_category.category_id] + [sub.category_id for sub in all_subcategories]

    # ✅ Fetch items belonging to this category or subcategories
    items = Item.query.filter(Item.category_id.in_(category_ids)).options(joinedload(Item.images)).all()

    return render_template('category.html', items=items, category=selected_category)
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

@index_bp.route('/ask', methods=['POST'])
def ask_question():
    data = request.get_json()
    question = data.get('question', '')
    
    if not question:
        return jsonify({'error': 'No question provided'}), 400
    
    try:
        # Detect if this is a generic question about what we sell
        generic_questions = [
            'what do you sell', 'what products do you have', 'what can i buy', 
            'what is available', 'what do you offer', 'show me products',
            'what items', 'list products', 'what categories'
        ]
        is_generic_question = any(gen_q in question.lower() for gen_q in generic_questions)
        
        # Get database information based on the question
        try:
            # Get all categories regardless of question type for context
            all_categories = Category.query.all()
            
            # Prepare items to search based on question type
            items = []
            
            if is_generic_question:
                # For generic questions, get a sampling of products across categories
                # This ensures we have something to show even for broad questions
                for category in all_categories:
                    # Get up to 2 items from each category for a good representative sample
                    category_items = Item.query.filter_by(category_id=category.category_id).limit(2).all()
                    items.extend(category_items)
            else:
                # For specific questions, perform keyword search
                keywords = [word.strip() for word in question.lower().split() if len(word.strip()) > 2]
                
                # Build filters for each keyword
                item_filters = []
                for keyword in keywords:
                    item_filters.append(Item.item_name.ilike(f'%{keyword}%'))
                    if hasattr(Item, 'item_description'):
                        item_filters.append(Item.item_description.ilike(f'%{keyword}%'))
                
                # Apply filters if we have any
                if item_filters:
                    items = Item.query.filter(or_(*item_filters)).all()
                    
                    # Log what was found for debugging
                    current_app.logger.info(f"Search for '{question}' found {len(items)} items")
                    for item in items[:3]:
                        current_app.logger.info(f"Match: {item.item_name} (${item.item_price})")
                
                # If no items found with keywords, try to find matching categories
                if not items and keywords:
                    category_filters = []
                    for keyword in keywords:
                        category_filters.append(Category.category_name.ilike(f'%{keyword}%'))
                    
                    if category_filters:
                        matching_categories = Category.query.filter(or_(*category_filters)).all()
                        
                        # Get items from matching categories
                        for category in matching_categories:
                            category_items = Item.query.filter_by(category_id=category.category_id).limit(5).all()
                            items.extend(category_items)
            
        except Exception as db_error:
            current_app.logger.error(f"Database error: {str(db_error)}")
            return jsonify({'error': 'Unable to search products. Please try again.'}), 500
        
        # Prepare product information for the AI prompt
        product_info_text = ""
        if items:
            product_details = []
            for item in items[:8]:  # Limit to 8 items for clarity
                detail = f"Product: {item.item_name}, Price: ${item.item_price}"
                if hasattr(item, 'item_description') and item.item_description:
                    # Add description if available and not empty
                    description = item.item_description.strip()
                    if description:
                        detail += f", Description: {description[:100]}"
                        if len(description) > 100:
                            detail += "..."
                
                # Add category if available
                if hasattr(item, 'category') and item.category:
                    detail += f", Category: {item.category.category_name}"
                
                product_details.append(detail)
            
            product_info_text = "\n".join(product_details)
        else:
            product_info_text = "No specific products found matching the query."
        
        # Prepare category information
        category_info = []
        
        # For all questions, include available categories
        if all_categories:
            category_names = [cat.category_name for cat in all_categories]
            category_info.append(f"Available categories: {', '.join(category_names)}")
        
        # For generic questions or if no specific products found, add sample items per category
        if is_generic_question or not items:
            for category in all_categories:
                sample_items = Item.query.filter_by(category_id=category.category_id).limit(3).all()
                if sample_items:
                    item_names = [item.item_name for item in sample_items]
                    category_info.append(f"Category '{category.category_name}' includes: {', '.join(item_names)}")
        
        category_info_text = "\n".join(category_info) if category_info else "No categories found in the database."

        # Prepare the prompt for the AI
        prompt = f"""You are a friendly and helpful shopping assistant for the Souq Khana e-commerce platform.
        
        IMPORTANT INSTRUCTIONS:
        - Respond in a conversational, helpful tone like a retail assistant would.
        - Be brief but engaging - keep responses under 3 sentences when possible.
        - NEVER use any kind of Markdown formatting in your responses.
        - Format your response as plain text only.
        - When mentioning prices, always include the dollar sign ($).
        - ONLY mention products or categories that are explicitly listed in the information below.
        - DO NOT make up any products or categories that aren't provided in the information.
        - If the product information section says "No specific products found", clearly state we don't currently have that item.
        - Address customers directly using "you" and refer to the store as "we" or "Souq Khana".
        - For generic questions about what we sell, mention our main categories and highlight some popular products.
        
        Here is information about products that might match the customer's query:
        {product_info_text}
        
        Here is information about our product categories:
        {category_info_text}
        
        Customer question: {question}"""

        # API call with timeout and error handling
        try:
            response = requests.post(
                url="https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {current_app.config['OPENROUTER_API_KEY']}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": request.host_url,
                    "X-Title": "Souq Khana"
                },
                json={
                    "model": "deepseek/deepseek-r1-zero:free",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.7,
                    "max_tokens": 300
                },
                timeout=15 
            )
            
            # Check response status
            response.raise_for_status()
            
            # Parse JSON and get the answer
            response_data = response.json()
            if 'choices' in response_data and len(response_data['choices']) > 0:
                answer = response_data['choices'][0]['message']['content']
                
                # Clean up answer - remove unwanted formatting
                answer = answer.replace('\\boxed{', '')
                answer = answer.replace('}', '')
                answer = answer.replace('```', '')
                
                # Double-check we're not returning empty responses
                if not answer.strip():
                    # Generate a basic fallback response using actual database content
                    fallback = "I'm sorry, I couldn't generate a specific response. "
                    
                    if all_categories:
                        category_names = [cat.category_name for cat in all_categories]
                        fallback += f"At Souq Khana, we offer products in these categories: {', '.join(category_names)}. "
                    
                    if items:
                        fallback += f"Some of our products include {', '.join([item.item_name for item in items[:5]])}. "
                        
                    fallback += "How can I help you find something specific today?"
                    return jsonify({'answer': fallback}), 200
                    
                return jsonify({'answer': answer}), 200
            else:
                current_app.logger.error(f"Unexpected API response structure: {response_data}")
                return jsonify({'error': 'Invalid response from AI service'}), 500
                
        except requests.exceptions.Timeout:
            current_app.logger.error("OpenRouter API timeout")
            return jsonify({'error': 'The service is taking too long to respond. Please try again later.'}), 504
            
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"OpenRouter API Error: {str(e)}")
            return jsonify({'error': 'Our product assistant is currently unavailable. Please try again later.'}), 503

    except Exception as e:
        current_app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred. Please try again later.'}), 500


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
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('admin.admin_register', secret_token=secret_token))
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('admin.admin_register', secret_token=secret_token))
        
        if not re.search(r'[A-Z]', password):
            flash('Password must contain at least one uppercase letter.', 'danger')
            return redirect(url_for('admin.admin_register', secret_token=secret_token))
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?]', password):
            flash('Password must contain at least one special character.', 'danger')
            return redirect(url_for('admin.admin_register', secret_token=secret_token))
            
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')

        if Admin.query.filter((Admin.username == username) | (Admin.email == email)).first():
            flash('Username or email already exists!', 'danger')
            return redirect(url_for('admin.admin_register', secret_token=secret_token))

        new_admin = Admin(username=username, email=email, password_hash=password_hash)
        db.session.add(new_admin)
        db.session.commit()

        s = Serializer(current_app.config['SECRET_KEY'])
        token = s.dumps({'admin_id': new_admin.admin_id})

        send_confirmation_email(email, token, 'admin')

        flash('Admin registered successfully! Please check your email to confirm your account.', 'success')
        return redirect(url_for('admin.admin_login'))

    return render_template('admin/admin_register.html', secret_token=secret_token)

@admin_bp.route('/admin/confirm/<token>')
def confirm_email(token):
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token, max_age=3600)
    except (SignatureExpired, BadSignature):
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('admin.admin_login'))

    admin = Admin.query.get(data['admin_id'])
    if not admin:
        flash('Admin not found.', 'danger')
        return redirect(url_for('admin.admin_login'))

    if admin.email_verified:
        flash('Account already confirmed. Please login.', 'success')
    else:
        admin.email_verified = True
        db.session.commit()
        flash('Your account has been confirmed. You can now log in.', 'success')

    return redirect(url_for('admin.admin_login'))

@admin_bp.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.verify_password(password):
            if not admin.email_verified:
                flash('Please confirm your email before logging in.', 'warning')
                return redirect(url_for('admin.admin_login'))
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
    new_status = request.form.get('status', '').strip().lower()
    cancellation_reason = request.form.get('cancellation_reason', '').strip()

    try:
        valid_statuses = ['sent', 'delivered', 'cancelled']
        if new_status not in valid_statuses:
            flash('Invalid status', 'danger')
            return redirect(url_for('admin.manage_orders'))

        order.order_status = new_status  
        
        if new_status == 'cancelled':
            if not cancellation_reason:
                flash('Cancellation reason required', 'danger')
                return redirect(url_for('admin.manage_orders'))
            order.cancellation_reason = cancellation_reason
        else:
            order.cancellation_reason = None

        db.session.commit()
        
        flash(f'Status updated to {new_status.title()}', 'success')

    except Exception as e:
        db.session.rollback()
        flash('Failed to update status', 'danger')

    return redirect(url_for('admin.manage_orders'))

@admin_bp.route('/admin/orders/<int:order_id>/process-refund', methods=['POST'])
@login_required
@admin_required
def process_refund(order_id):
    stripe.api_key = current_app.config['STRIPE_SECRET_KEY']
    order = Order.query.get_or_404(order_id)
    action = request.form.get('action', '').lower()
    denial_reason = request.form.get('denial_reason', '').strip()

    try:
        if action == 'approve':
            if order.payment_method != 'cash_on_delivery':
                try:
                    stripe.Refund.create(
                        payment_intent=order.stripe_payment_intent,
                        reason='requested_by_customer'
                    )
                except StripeError as e:
                    flash(f'Stripe error: {e.user_message}', 'danger')
                    return redirect(url_for('admin.manage_orders'))

            order.refund_status = 'approved'
            order.order_status = 'refunded'
            message_content = f"Refund approved for Order #{order.order_id}"

        elif action == 'deny':
            if not denial_reason:
                flash('Denial reason is required', 'danger')
                return redirect(url_for('admin.manage_orders'))
            order.refund_status = 'denied'
            order.refund_denial_reason = denial_reason
            message_content = f"Refund denied: {denial_reason}"
        else:
            flash('Invalid action', 'danger')
            return redirect(url_for('admin.manage_orders'))

        message = Messages(
            user_id=order.user_id,
            order_id=order.order_id,
            content=message_content
        )
        db.session.add(message)
        db.session.commit() 
        flash('Refund processed successfully', 'success')

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Refund processing error: {str(e)}")
        flash('Failed to process refund.', 'danger')

    return redirect(url_for('admin.manage_orders'))

@admin_bp.route('/admin/orders/<int:order_id>/process-cancel', methods=['POST'])
@login_required
@admin_required
def process_cancel(order_id):
    order = Order.query.get_or_404(order_id)
    action = request.form.get('action', '').lower() 
    denial_reason = request.form.get('denial_reason', '').strip()

    try:
        if action == 'approve':
            order.order_status = 'cancelled'
            order.cancel_status = 'approved'
            message_content = "Cancellation approved"
            
            message = Messages(
                user_id=order.user_id,
                order_id=order.order_id,
                content=message_content
            )
            db.session.add(message)
            
        elif action == 'deny':
            if not denial_reason:
                flash('Denial reason is required', 'danger')
                return redirect(url_for('admin.manage_orders'))
            
            order.cancel_status = 'denied'
            order.cancel_denial_reason = denial_reason
            message_content = f"Cancellation denied: {denial_reason}"
            
            message = Messages(
                user_id=order.user_id,
                order_id=order.order_id,
                content=message_content
            )
            db.session.add(message)
        else:
            flash('Invalid action', 'danger')
            return redirect(url_for('admin.manage_orders'))

        db.session.commit()
        flash('Cancellation processed successfully', 'success')
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Cancellation processing error: {str(e)}")
        flash('Failed to process cancellation. Please try again.', 'danger')

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
    if current_user.is_authenticated:
        if current_user.role != 'user':
            return redirect(url_for("index.index"))
        flash('You are already logged in!', 'warning')
        return redirect(url_for('index.index'))

    if request.method == 'POST':
        username = request.form['username']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('user.user_register'))
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('user.user_register'))
        
        if not re.search(r'[A-Z]', password):
            flash('Password must contain at least one uppercase letter.', 'danger')
            return redirect(url_for('user.user_register'))
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?]', password):
            flash('Password must contain at least one special character.', 'danger')
            return redirect(url_for('user.user_register'))
        
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')

        if User.query.filter((User.username == username) | (User.user_email == email)).first():
            flash('Username or email already exists!', 'danger')
            return redirect(url_for('user.user_register'))

        new_user = User(
            username=username,
            first_name=first_name,
            last_name=last_name,
            user_email=email,
            password_hash=password_hash
        )
        db.session.add(new_user)
        db.session.commit()

        s = Serializer(current_app.config['SECRET_KEY'])
        token = s.dumps({'user_id': new_user.user_id})

        send_confirmation_email(email, token, 'user')

        flash('User registered successfully! Please check your email to confirm your account.', 'success')
        return redirect(url_for('user.user_login'))

    return render_template('user/user_register.html', show_footer=True)

@user_bp.route('/user/confirm/<token>')
def confirm_email(token):
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token, max_age=3600)
    except (SignatureExpired, BadSignature):
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('user.user_login'))

    user = User.query.get(data['user_id'])
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('user.user_login'))

    if user.email_verified:
        flash('Account already confirmed. Please login.', 'success')
    else:
        user.email_verified = True
        db.session.commit()
        flash('Your account has been confirmed. You can now log in.', 'success')

    return redirect(url_for('user.user_login'))

@user_bp.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if current_user.is_authenticated:
        flash('You are already logged in!', 'info')
        return redirect(url_for('index.index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.verify_password(password):
            if not user.email_verified:
                flash('Please confirm your email before logging in.', 'warning')
                return redirect(url_for('user.user_login'))
            
            login_user(user)
            session['user_type'] = 'user'
            flash('Login successful!', 'success')
            return redirect(url_for('index.index'))
        
        flash('Invalid username or password', 'danger')
        return redirect(url_for('user.user_login'))

    return render_template('user/user_login.html', show_footer=True)


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
    return render_template('user/user_dashboard.html', user=current_user, addresses=addresses, show_footer=True)

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
    return render_template('user/user_profile.html', user=current_user, show_footer=True)

# Change Password
@user_bp.route('/user/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not check_password_hash(current_user.password_hash, current_password):
            return jsonify({'status': 'error', 'message': 'Current password is incorrect.'}), 400

        if new_password != confirm_password:
            return jsonify({'status': 'error', 'message': 'New passwords do not match.'}), 400

        current_user.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
        db.session.commit()

        flash('Password changed successfully!', 'success')
        
        return jsonify({'status': 'success', 'message': 'Password changed successfully!', 'redirect': url_for('user.user_dashboard')}), 200

    return render_template('user/change_password.html')

@user_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(user_email=email).first()
        
        if user:
            s = Serializer(current_app.config['SECRET_KEY'])
            token = s.dumps({'user_id': user.user_id, 'type': 'reset'})
            
            reset_url = url_for('user.reset_password', token=token, _external=True)
            
            msg = Message('Reset Your Password',
                        sender=current_app.config['MAIL_DEFAULT_SENDER'],
                        recipients=[email])
            msg.html = render_template('emails/reset_password.html', reset_url=reset_url)
            mail.send(msg)
            
            current_app.logger.info(f"Password reset email sent to {email}")
        
        flash('If an account exists with that email, we have sent password reset instructions.', 'info')
        return redirect(url_for('user.user_login'))
    
    return render_template('user/forgot_password.html', show_footer=True)

@user_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token, max_age=3600) 
        if not data or 'user_id' not in data or data.get('type') != 'reset':
            flash('Invalid or expired reset link. Please try again.', 'danger')
            return redirect(url_for('user.forgot_password'))
    except (SignatureExpired, BadSignature):
        flash('Invalid or expired reset link. Please try again.', 'danger')
        return redirect(url_for('user.forgot_password'))
    
    user = User.query.get(data['user_id'])
    if not user:
        flash('Invalid or expired reset link. Please try again.', 'danger')
        return redirect(url_for('user.forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate password
        if not password or len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('user/reset_password.html', token=token, show_footer=True)
        
        if not re.search(r'[A-Z]', password):
            flash('Password must contain at least one uppercase letter.', 'danger')
            return render_template('user/reset_password.html', token=token, show_footer=True)
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?]', password):
            flash('Password must contain at least one special character.', 'danger')
            return render_template('user/reset_password.html', token=token, show_footer=True)
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('user/reset_password.html', token=token, show_footer=True)
        
        user.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        db.session.commit()
        
        flash('Your password has been updated. You can now log in with your new password.', 'success')
        return redirect(url_for('user.user_login'))
    
    return render_template('user/reset_password.html', token=token, show_footer=True)


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
        country = "Iraq"  # Set country to Iraq
        phone_number = request.form['phone_number'].strip()  # Remove spaces
        governorate = request.form.get('governorate')
        is_default = 'is_default' in request.form  # Check if the checkbox is checked

        # Debugging: Log the phone number input
        print(f"DEBUG: Phone Number Input: '{phone_number}'")

        # Ensure phone number contains only digits and has a length of 11
        if not phone_number.isdigit() or len(phone_number) != 11:
            flash("Phone number must contain exactly 11 numeric digits.", "danger")
            return render_template('user/add_address.html', governorates=IRAQ_GOVERNORATES)

        # Validate phone number for Iraq
        iraq_phone_pattern = r"^07\d{9}$"  # Matches exactly 07XXXXXXXXX (11 digits)
        if not re.match(iraq_phone_pattern, phone_number):
            flash("Invalid phone number format for Iraq. Use format: 07XXXXXXXXX (11 digits).", "danger")
            return render_template('user/add_address.html', governorates=IRAQ_GOVERNORATES)

        # Handle governorate for Iraq
        if not governorate:
            flash("Governorate is required for Iraq.", "danger")
            return render_template('user/add_address.html', governorates=IRAQ_GOVERNORATES)

        # Automatically set the first address as default if no default exists
        if not Address.query.filter_by(user_id=current_user.user_id, is_default=True).count():
            is_default = True

        # Unset default for other addresses if this is set as default
        if is_default:
            Address.query.filter_by(user_id=current_user.user_id, is_default=True).update({'is_default': False})

        new_address = Address(
            user_id=current_user.user_id,
            address_line=address_line,
            city=city,
            governorate=governorate,
            country=country,
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

    return render_template('user/add_address.html', governorates=IRAQ_GOVERNORATES)

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
        country = "Iraq"  # Set country to Iraq
        phone_number = request.form['phone_number'].strip()  # Remove spaces
        governorate = request.form.get('governorate')
        is_default = 'is_default' in request.form

        # Debugging: Log the phone number input
        print(f"DEBUG: Phone Number Input: '{phone_number}'")

        # Ensure phone number contains only digits and has a length of 11
        if not phone_number.isdigit() or len(phone_number) != 11:
            flash("Phone number must contain exactly 11 numeric digits.", "danger")
            return render_template('user/edit_address.html', address=address, governorates=IRAQ_GOVERNORATES)

        # Validate phone number for Iraq
        iraq_phone_pattern = r"^07\d{9}$"  # Matches exactly 07XXXXXXXXX (11 digits)
        if not re.match(iraq_phone_pattern, phone_number):
            flash("Invalid phone number format for Iraq. Use format: 07XXXXXXXXX (11 digits).", "danger")
            return render_template('user/edit_address.html', address=address, governorates=IRAQ_GOVERNORATES)

        # Handle governorate for Iraq
        if not governorate:
            flash("Governorate is required for Iraq.", "danger")
            return render_template('user/edit_address.html', address=address, governorates=IRAQ_GOVERNORATES)

        # Unset default for other addresses if this is set as default
        if is_default:
            Address.query.filter_by(user_id=current_user.user_id, is_default=True).update({'is_default': False})

        # Update address fields
        address.address_line = address_line
        address.city = city
        address.governorate = governorate
        address.country = country
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

    return render_template('user/edit_address.html', address=address, governorates=IRAQ_GOVERNORATES)

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
    except IntegrityError as e:
        db.session.rollback()
        if "foreign key constraint fails" in str(e):
            flash("Cannot delete address. It is associated with one or more orders.", "danger")
        else:
            flash(f"An error occurred: {str(e)}", "danger")
    except Exception as e:
        db.session.rollback()
        flash(f"An error occurred: {str(e)}", "danger")

    return redirect(url_for('user.user_dashboard'))

# user payments

@user_bp.route('/user/payments')
@login_required
def user_payments():
    payment_methods = PaymentMethod.query.filter_by(user_id=current_user.user_id).all()
    
    # Check if this is an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return render_template('user/payment_methods_list_ajax.html', payment_methods=payment_methods)
    
    # Regular request returns the full template
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

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': True, 
                'message': 'Payment method added successfully!'
            })
        
        flash("Payment method added successfully!", "success")
        return redirect(url_for('user.user_payments'))
    
    # GET request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return render_template('user/add_payment_method_ajax.html')
    
    return render_template('user/add_payment_method.html')


@user_bp.route('/user/payments/<int:payment_id>/set-default', methods=['POST'])
@login_required
def set_default_payment_method(payment_id):
    payment = PaymentMethod.query.get_or_404(payment_id)

    # Ensure the user owns the payment method
    if payment.user_id != current_user.user_id:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'Unauthorized action.'})
        
        flash("Unauthorized action.", "danger")
        return redirect(url_for('user.user_payments'))

    try:
        # Unset the current default payment method
        PaymentMethod.query.filter_by(user_id=current_user.user_id, is_default=True).update({'is_default': False})

        # Set the selected payment method as the default
        payment.is_default = True
        db.session.commit()

        # Update Stripe customer's default payment method
        stripe.api_key = current_app.config['STRIPE_SECRET_KEY']
        stripe.Customer.modify(
            current_user.stripe_customer_id,
            invoice_settings={
                'default_payment_method': payment.stripe_payment_method_id
            }
        )
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            payment_methods = PaymentMethod.query.filter_by(user_id=current_user.user_id).all()
            html = render_template('user/payment_methods_list_ajax.html', payment_methods=payment_methods)
            return jsonify({
                'success': True, 
                'message': 'Default payment method updated successfully!',
                'html': html
            })

        flash("Default payment method updated successfully!", "success")
    except Exception as e:
        db.session.rollback()
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'})
        
        flash(f"An error occurred: {str(e)}", "danger")

    return redirect(url_for('user.user_payments'))


@user_bp.route('/user/payments/<int:payment_id>/delete', methods=['POST'])
@login_required
def delete_payment_method(payment_id):
    payment = PaymentMethod.query.get_or_404(payment_id)

    # Ensure the user owns the payment method
    if payment.user_id != current_user.user_id:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'Unauthorized action.'})
        
        flash("Unauthorized action.", "danger")
        return redirect(url_for('user.user_payments'))

    try:
        db.session.delete(payment)
        db.session.commit()
        reset_auto_increment(db, 'payment_methods', 'payment_id')
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            payment_methods = PaymentMethod.query.filter_by(user_id=current_user.user_id).all()
            html = render_template('user/payment_methods_list_ajax.html', payment_methods=payment_methods)
            return jsonify({
                'success': True, 
                'message': 'Payment method deleted successfully!',
                'html': html
            })
        
        flash("Payment method deleted successfully!", "success")
    except Exception as e:
        db.session.rollback()
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'})
        
        flash(f"An error occurred: {str(e)}", "danger")

    return redirect(url_for('user.user_payments'))


# User Messages
@user_bp.route('/user/messages')
@login_required
def user_messages():
    messages = Messages.query.filter_by(user_id=current_user.user_id).order_by(Messages.created_at.desc()).all()
    return render_template('user/messages.html', messages=messages)

@user_bp.route('/user/messages/<int:message_id>/mark-read', methods=['POST'])
@login_required
def mark_message_read(message_id):
    message = Messages.query.get_or_404(message_id)
    if message.user_id != current_user.user_id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('user.user_messages'))
    
    message.is_read = True
    db.session.commit()
    return redirect(url_for('user.user_messages'))

@user_bp.route('/user/messages/mark-all-read', methods=['POST'])
@login_required
def mark_all_messages_read():
    messages = Messages.query.filter_by(user_id=current_user.user_id, is_read=False).all()
    for message in messages:
        message.is_read = True
    db.session.commit()
    flash('All messages marked as read.', 'success')
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

    print(f"DEBUG: Item details {item.__dict__}")  # Prints all attributes
    return render_template('item_detail.html', item=item)

# Cart Routes
@cart_bp.route('/cart')
@login_required
def view_cart():
    cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
    return render_template('cart.html', cart=cart ,show_footer=True)


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
    return render_template('wishlist.html', wishlist=wishlist ,show_footer=True)


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
        # Handle Cash on Delivery
        if payment_method_id == 'cash_on_delivery':
            return process_cash_on_delivery(address_id)

        # Store the selected address and payment method in the session
        session['address_id'] = address_id
        session['payment_method_id'] = payment_method_id

        return render_template('redirect_to_stripe.html')

    return render_template('checkout.html', cart=cart, addresses=addresses, payment_methods=payment_methods)

def process_cash_on_delivery(address_id):
    address = Address.query.get(address_id)
    if not address or address.user_id != current_user.user_id:
        flash('Invalid shipping address', 'danger')
        return redirect(url_for('order.checkout'))

    cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
    if not cart or not cart.items:
        flash('Your cart is empty', 'danger')
        return redirect(url_for('cart.view_cart'))

    total_amount = sum(item.item.item_price * item.quantity for item in cart.items)

    new_order = Order(
        user_id=current_user.user_id,
        shipping_address_id=address_id,
        total_amount=total_amount,
        order_status='pending',
        payment_method='cash_on_delivery',
        payment_received=False
    )
    db.session.add(new_order)

    message = Messages(
        user_id=current_user.user_id,
        order_id=new_order.order_id,
        content=f"Order placed with Cash on Delivery. Total: ${total_amount}"
    )
    db.session.add(message)

    CartItem.query.filter_by(cart_id=cart.cart_id).delete()
    db.session.commit()

    flash('Order placed! Pay upon delivery.', 'success')
    return redirect(url_for('order.view_orders'))


@order_bp.route('/stripe_checkout_session', methods=['POST'])
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
            stripe_payment_intent=payment_intent_id or checkout_session.payment_intent,
            payment_method='stripe'
        )

        db.session.add(new_order)

        message = Messages(
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
    
    valid_statuses = ['payment_successful, delivery pending', 'pending']
    if order.order_status not in valid_statuses:
        flash('This order cannot be canceled.', 'danger')
        return redirect(url_for('order.view_orders'))
    
    try:
        if order.payment_method != 'cash_on_delivery':
            stripe.api_key = current_app.config['STRIPE_SECRET_KEY']
            current_app.logger.info(f"Attempting refund for PaymentIntent: {order.stripe_payment_intent}")
            
            refund = stripe.Refund.create(
                payment_intent=order.stripe_payment_intent,
                amount=int(order.total_amount * 100),
                reason='requested_by_customer'
            )
            current_app.logger.info(f"Refund created: {refund.id}")
        
        order.order_status = 'cancelled'
        
        message_content = (f"Order #{order.order_id} has been cancelled and refund processed." 
                          if order.payment_method != 'cash_on_delivery' 
                          else f"Order #{order.order_id} has been cancelled.")
        
        message = Messages(
            user_id=current_user.user_id,
            order_id=order.order_id,
            content=message_content
        )
        
        db.session.add(message)
        db.session.commit()
        flash(message_content, 'success')
        
    except stripe.error.StripeError as e:
        db.session.rollback()
        current_app.logger.error(f"Stripe Error during refund: {str(e)}")
        flash(f'Refund failed: {e.user_message}', 'danger')
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error cancelling order: {str(e)}")
        flash(f'Error cancelling order: {str(e)}', 'danger')
    
    return redirect(url_for('order.view_orders'))

@order_bp.route('/orders/<int:order_id>/request-refund', methods=['POST'])
@login_required
def request_refund(order_id):
    order = Order.query.get_or_404(order_id)
    refund_reason = request.form.get('refund_reason', '').strip()

    # Validation checks
    if order.user_id != current_user.user_id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('order.view_orders'))
    
    if order.order_status != 'sent' or order.payment_method == 'cash_on_delivery':
        flash('Refund not allowed for this order.', 'danger')
        return redirect(url_for('order.view_orders'))

    if not refund_reason:
        flash('Please provide a refund reason.', 'danger')
        return redirect(url_for('order.order_detail', order_id=order_id))

    order.refund_requested = True
    order.refund_reason = refund_reason
    order.refund_status = 'pending'
    db.session.commit()

    flash('Refund request submitted. An admin will review it shortly.', 'success')
    return redirect(url_for('order.view_orders'))

@order_bp.route('/orders/<int:order_id>/request-cancel', methods=['POST'])
@login_required
def request_cancel(order_id):
    order = Order.query.get_or_404(order_id)
    
    if order.user_id != current_user.user_id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('order.view_orders'))
    
    if order.payment_method != 'cash_on_delivery' or order.order_status != 'sent':
        flash('Cancellation not available for this order.', 'danger')
        return redirect(url_for('order.view_orders'))

    order.cancel_requested = True
    order.cancel_status = 'pending'
    db.session.commit()
    
    flash('Cancellation request submitted.', 'success')
    return redirect(url_for('order.view_orders'))
