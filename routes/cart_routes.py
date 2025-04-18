from routes.common import *

# Blueprint
cart_bp = Blueprint('cart', __name__)

@cart_bp.route('/cart')
@login_required
def view_cart():
    cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
    total_price = sum(item.quantity * item.item.item_price for item in cart.items) if cart else 0
    return render_template('cart.html', cart=cart, total_price=total_price, show_footer=True)

@cart_bp.route('/cart/add/<int:item_id>', methods=['POST'])
def add_to_cart(item_id):
    if not current_user.is_authenticated:
        return jsonify({
            'success': False,
            'error': 'Please login to add items to your cart',
            'require_login': True
        }), 401
    try:
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
        
        cart_count = sum(item.quantity for item in cart.items)
        return jsonify({
            'success': True,
            'cart_count': cart_count,
            'message': 'Item added to cart!'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@cart_bp.route('/cart/update/<int:cart_item_id>', methods=['POST'])
@login_required
def update_cart_item(cart_item_id):
    try:
        cart_item = CartItem.query.get_or_404(cart_item_id)
        if cart_item.cart.user_id != current_user.user_id:
            return jsonify({'error': 'Unauthorized'}), 403

        data = request.get_json()
        action = data.get('action')

        if not action:
            return jsonify({'error': 'Invalid request, no action provided'}), 400

        if action == 'increase':
            cart_item.quantity += 1
        elif action == 'decrease':
            if cart_item.quantity > 1:
                cart_item.quantity -= 1
            else:
                return jsonify({'error': 'Cannot decrease quantity below 1'}), 400
        else:
            return jsonify({'error': 'Invalid action'}), 400

        db.session.commit()

        total_price = cart_item.quantity * cart_item.item.item_price

        cart_total = sum(item.quantity * item.item.item_price for item in cart_item.cart.items)

        return jsonify({
            'message': 'Cart updated successfully',
            'quantity': cart_item.quantity,
            'total_price': total_price,
            'cart_total': cart_total
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@cart_bp.route('/cart/remove/<int:cart_item_id>', methods=['POST'])
@login_required
def remove_from_cart(cart_item_id):
    try:
        cart_item = CartItem.query.get_or_404(cart_item_id)

        if cart_item.cart.user_id != current_user.user_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403

        db.session.delete(cart_item)
        db.session.commit()
        
        cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
        cart_items = [{
            "cart_item_id": item.cart_item_id,
            "name": item.item.item_name,
            "price": item.item.item_price,
            "quantity": item.quantity,
            "total_price": item.item.item_price * item.quantity,
            "image_url": item.item.images[0].image_url if item.item.images else "no_image.png"
        } for item in cart.items] if cart else []
        
        cart_total = sum(item.quantity * item.item.item_price for item in cart.items) if cart and cart.items else 0

        return jsonify({
            'success': True,
            'cart_count': sum(item["quantity"] for item in cart_items) if cart_items else 0,
            'cart_items': cart_items,
            'cart_total': cart_total
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@cart_bp.route('/cart/move-to-wishlist/<int:cart_item_id>', methods=['POST'])
@login_required
def move_to_wishlist(cart_item_id):
    cart_item = CartItem.query.get_or_404(cart_item_id)

    if cart_item.cart.user_id != current_user.user_id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('cart.view_cart'))

    wishlist = Wishlist.query.filter_by(user_id=current_user.user_id).first()
    if not wishlist:
        wishlist = Wishlist(user_id=current_user.user_id)
        db.session.add(wishlist)
        db.session.commit()

    wishlist_item = WishlistItem.query.filter_by(wishlist_id=wishlist.wishlist_id, item_id=cart_item.item_id).first()
    if not wishlist_item:
        wishlist_item = WishlistItem(wishlist_id=wishlist.wishlist_id, item_id=cart_item.item_id)
        db.session.add(wishlist_item)

    db.session.delete(cart_item)
    reset_auto_increment(db, 'cart_items', 'cart_item_id')
    db.session.commit()

    flash('Item moved to wishlist!', 'success')
    return redirect(url_for('cart.view_cart'))