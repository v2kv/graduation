from routes.common import *

# Blueprint
user_bp = Blueprint('user', __name__)

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
from flask import jsonify

@user_bp.route('/user/address/adds', methods=['POST'])
@login_required
def adds_address():
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        address_line = request.form['address_line']
        city = request.form['city']
        country = "Iraq"
        phone_number = request.form['phone_number'].strip()
        governorate = request.form.get('governorate')
        is_default = 'is_default' in request.form

        # Phone validation
        if not phone_number.isdigit() or len(phone_number) != 11:
            return jsonify(success=False, message="Phone number must contain exactly 11 numeric digits.")

        iraq_phone_pattern = r"^07\d{9}$"
        if not re.match(iraq_phone_pattern, phone_number):
            return jsonify(success=False, message="Invalid phone number format for Iraq. Use: 07XXXXXXXXX.")

        if not governorate:
            return jsonify(success=False, message="Governorate is required for Iraq.")

        # Default address logic
        if not Address.query.filter_by(user_id=current_user.user_id, is_default=True).count():
            is_default = True
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
            return jsonify(success=True, message="Address added successfully!")
        except Exception as e:
            db.session.rollback()
            return jsonify(success=False, message=f"Database error: {str(e)}")

    # Fallback for normal request (optional)
    flash("Invalid request", "danger")
    return redirect(url_for('user.add_address'))
# Add Address
@user_bp.route('/user/address/add', methods=['GET', 'POST'])
@login_required
def add_address():
    if request.method == 'POST':
        address_line = request.form['address_line']
        city = request.form['city']
        country = "Iraq"  
        phone_number = request.form['phone_number'].strip() 
        governorate = request.form.get('governorate')
        is_default = 'is_default' in request.form 

        if not phone_number.isdigit() or len(phone_number) != 11:
            flash("Phone number must contain exactly 11 numeric digits.", "danger")
            return render_template('user/add_address.html', governorates=IRAQ_GOVERNORATES)

        # Validate phone number for Iraq
        iraq_phone_pattern = r"^07\d{9}$"  # Matches exactly 07XXXXXXXXX (11 digits)
        if not re.match(iraq_phone_pattern, phone_number):
            flash("Invalid phone number format for Iraq. Use format: 07XXXXXXXXX (11 digits).", "danger")
            return render_template('user/add_address.html', governorates=IRAQ_GOVERNORATES)

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
    addresses = Address.query.filter_by(user_id=current_user.user_id).all()
    return render_template('user/add_address.html', governorates=IRAQ_GOVERNORATES,addresses=addresses,show_footer=True)

# Edit Address
@user_bp.route('/user/address/<int:address_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_address(address_id):
    address = Address.query.get_or_404(address_id)

    if address.user_id != current_user.user_id:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('user.user_dashboard'))

    if request.method == 'POST':
        address_line = request.form['address_line']
        city = request.form['city']
        country = "Iraq" 
        phone_number = request.form['phone_number'].strip()  # Remove spaces
        governorate = request.form.get('governorate')
        is_default = 'is_default' in request.form

        if not phone_number.isdigit() or len(phone_number) != 11:
            flash("Phone number must contain exactly 11 numeric digits.", "danger")
            return render_template('user/edit_address.html', address=address, governorates=IRAQ_GOVERNORATES)

        iraq_phone_pattern = r"^07\d{9}$" 
        if not re.match(iraq_phone_pattern, phone_number):
            flash("Invalid phone number format for Iraq. Use format: 07XXXXXXXXX (11 digits).", "danger")
            return render_template('user/edit_address.html', address=address, governorates=IRAQ_GOVERNORATES)

        if not governorate:
            flash("Governorate is required for Iraq.", "danger")
            return render_template('user/edit_address.html', address=address, governorates=IRAQ_GOVERNORATES)

        if is_default:
            Address.query.filter_by(user_id=current_user.user_id, is_default=True).update({'is_default': False})

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

    Address.query.filter_by(user_id=current_user.user_id, is_default=True).update({'is_default': False})

    address.is_default = True
    db.session.commit()

    flash('Default address updated successfully!', 'success')
    return redirect(url_for('user.user_dashboard'))

@user_bp.route('/user/address/<int:address_id>/delete', methods=['POST'])
@login_required
def delete_address(address_id):
    address = Address.query.get_or_404(address_id)

    if address.user_id != current_user.user_id:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('user.user_dashboard'))

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
    return render_template('user/messages.html', messages=messages,show_footer=True)

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