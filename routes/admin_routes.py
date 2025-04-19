from routes.common import *

# Blueprint
admin_bp = Blueprint('admin', __name__)

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

    for image in item.images:
        delete_image(image.image_url) 
        db.session.delete(image)
        reset_auto_increment(db, 'product_images', 'image_id')

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
    new_status = request.form.get('status', '').strip()
    cancellation_reason = request.form.get('cancellation_reason', '').strip()

    try:
        valid_statuses = ['pending', 'payment_successful, delivery pending', 'sent', 'delivered', 'cancelled']
        if new_status not in valid_statuses:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'message': 'Invalid status'})
            flash('Invalid status', 'danger')
            return redirect(url_for('admin.manage_orders'))

        order.order_status = new_status  
        
        if new_status == 'cancelled':
            if not cancellation_reason:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'success': False, 'message': 'Cancellation reason required'})
                flash('Cancellation reason required', 'danger')
                return redirect(url_for('admin.manage_orders'))
            order.cancellation_reason = cancellation_reason
        else:
            order.cancellation_reason = None

        db.session.commit()
        
        message = Messages(
            user_id=order.user_id,
            order_id=order.order_id,
            content=f"Your order status has been updated to: {new_status.title()}"
        )
        db.session.add(message)
        db.session.commit()

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True})
        flash(f'Status updated to {new_status.title()}', 'success')

    except Exception as e:
        db.session.rollback()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'Failed to update status'})
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