from routes.common import *

# Blueprint
order_bp = Blueprint('order', __name__)

@order_bp.route('/orders')
@login_required
def view_orders():
    orders = Order.query.filter_by(user_id=current_user.user_id).order_by(Order.order_date.desc()).all()
                
    return render_template('order_list.html', orders=orders, show_footer=True)

@order_bp.route('/orders/<int:order_id>')
@login_required
def order_detail(order_id):
    order = Order.query.get_or_404(order_id)
    return render_template('order_detail.html', order=order,show_footer=True)

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

        if not address_id or not payment_method_id:
            flash('Please select both an address and a payment method.', 'danger')
            return redirect(url_for('order.checkout'))
        if payment_method_id == 'cash_on_delivery':
            return process_cash_on_delivery(address_id)

        session['address_id'] = address_id
        session['payment_method_id'] = payment_method_id

        return render_template('redirect_to_stripe.html')

    return render_template('checkout.html', cart=cart, addresses=addresses, payment_methods=payment_methods ,show_footer=True)

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

        if payment_method_id and payment_method_id != 'new':
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

                PaymentMethod.query.filter_by(
                    user_id=current_user.user_id, 
                    is_default=True
                ).update({'is_default': False})
                
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
            payment_intent = stripe.PaymentIntent.retrieve(payment_intent_id)
            metadata = payment_intent.metadata
        elif session_id:
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