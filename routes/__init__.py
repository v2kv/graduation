from routes.index_routes import index_bp
from routes.admin_routes import admin_bp
from routes.user_routes import user_bp
from routes.item_routes import item_bp
from routes.cart_routes import cart_bp
from routes.wishlist_routes import wishlist_bp
from routes.order_routes import order_bp

# Export all blueprints
__all__ = ['index_bp', 'admin_bp', 'user_bp', 'item_bp', 'cart_bp', 'wishlist_bp', 'order_bp']