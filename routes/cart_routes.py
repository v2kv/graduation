from routes.common import *

# Blueprint
cart_bp = Blueprint('cart', __name__)

@cart_bp.route('/cart')
@login_required
def view_cart():
    cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
    return render_template('cart.html', cart=cart, show_footer=True)

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