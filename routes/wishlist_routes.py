from routes.common import *

# Blueprint
wishlist_bp = Blueprint('wishlist', __name__)

@wishlist_bp.route('/wishlist')
@login_required
def view_wishlist():
    wishlist = Wishlist.query.filter_by(user_id=current_user.user_id).first()
    return render_template('wishlist.html', wishlist=wishlist, show_footer=True)

@wishlist_bp.route('/wishlist/add/<int:item_id>', methods=['POST'])
def add_to_wishlist(item_id):
    # Check if user is logged in
    if not current_user.is_authenticated:
        return jsonify({
            'success': False,
            'error': 'Please login to add items to your wishlist',
            'require_login': True
        }), 401
    
    try:
        item = Item.query.get_or_404(item_id)
        wishlist = Wishlist.query.filter_by(user_id=current_user.user_id).first()
        
        if not wishlist:
            wishlist = Wishlist(user_id=current_user.user_id)
            db.session.add(wishlist)
            db.session.commit()

        # Check if the item is already in the wishlist
        existing_item = WishlistItem.query.filter_by(
            wishlist_id=wishlist.wishlist_id, 
            item_id=item_id
        ).first()
        
        if existing_item:
            return jsonify({
                'success': True,
                'message': 'Item already in wishlist',
                'wishlist_count': len(wishlist.items)
            })
        
        # Add the new item to wishlist
        wishlist_item = WishlistItem(wishlist_id=wishlist.wishlist_id, item_id=item_id)
        db.session.add(wishlist_item)
        db.session.commit()
        
        # Get updated wishlist count
        updated_count = WishlistItem.query.filter_by(wishlist_id=wishlist.wishlist_id).count()
        
        return jsonify({
            'success': True, 
            'message': 'Item added to wishlist!',
            'wishlist_count': updated_count
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

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