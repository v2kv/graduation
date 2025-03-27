from db import db
from flask_login import UserMixin
from werkzeug.security import check_password_hash


class Admin(UserMixin, db.Model):
    __tablename__ = 'admins'
    admin_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False, default='admin')
    created_at = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    email_verified = db.Column(db.Boolean, nullable=False, default=False)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.admin_id)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    role = db.Column(db.String(20), nullable=False,default="user")
    user_email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp())
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    email_verified = db.Column(db.Boolean, nullable=False, default=False)
    stripe_customer_id = db.Column(db.String(255), nullable=True)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.user_id)
    
class Address(db.Model):
    __tablename__ = 'addresses'
    address_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    user = db.relationship('User', backref=db.backref('addresses', lazy=True))
    address_line = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(50), nullable=False)
    governorate = db.Column(db.String(50), nullable=True)
    country = db.Column(db.String(50), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    is_default = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return f"<Address {self.address_line}, {self.city}, {self.country}>"

class PaymentMethod(db.Model):
    __tablename__ = 'payment_methods'

    payment_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id', ondelete='CASCADE'), nullable=False)
    issuer = db.Column(db.String(50), nullable=False)
    last_four_digits = db.Column(db.String(4), nullable=False)
    expiry_month = db.Column(db.Integer, nullable=False)
    expiry_year = db.Column(db.SmallInteger, nullable=False)
    stripe_payment_method_id = db.Column(db.String(255), nullable=False)  # PaymentMethod ID from Stripe
    is_default = db.Column(db.Boolean, nullable=False, default=False)  # Track default payment method
    created_at = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp(),
                           onupdate=db.func.current_timestamp())

    user = db.relationship('User', backref=db.backref('payment_methods', cascade='all, delete-orphan'))

    def __repr__(self):
        return f"<PaymentMethod(payment_id={self.payment_id}, issuer={self.issuer}, last_four_digits={self.last_four_digits}, is_default={self.is_default})>"

class Category(db.Model):
    __tablename__ = 'categories'
    category_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    category_name = db.Column(db.String(50), nullable=False, unique=True)
    parent_category_id = db.Column(db.Integer, db.ForeignKey('categories.category_id'))
    
    # Self-referential relationship for parent-child hierarchy
    parent_category = db.relationship('Category', remote_side=[category_id], backref=db.backref('subcategories', lazy=True))

    def __repr__(self):
        return f"<Category(id={self.category_id}, name='{self.category_name}', parent_id={self.parent_category_id})>"

class Item(db.Model):
    __tablename__ = 'items'
    item_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    item_name = db.Column(db.String(100), nullable=False)
    item_description = db.Column(db.Text)
    item_price = db.Column(db.Numeric(10, 2), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.category_id'), nullable=False)
    category = db.relationship('Category', backref=db.backref('items', lazy=True))
    created_at = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

    # Many-to-Many relationship with Tag
    tags = db.relationship(
        'Tag',
        secondary='item_tags',  # Association table
        backref=db.backref('items', lazy='dynamic'),
        lazy=True
    )


class ItemVariation(db.Model):
    __tablename__ = 'item_variations'
    variation_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    item_id = db.Column(db.Integer, db.ForeignKey('items.item_id'), nullable=False)
    item = db.relationship('Item', backref=db.backref('variations', lazy=True))
    variation_name = db.Column(db.String(100), nullable=False)
    variation_value = db.Column(db.String(100), nullable=False)
    price_modifier = db.Column(db.Numeric(10, 2), default=0.00)
    quantity = db.Column(db.Integer, nullable=False, default=0)

class Tag(db.Model):
    __tablename__ = 'tags'
    tag_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tag_name = db.Column(db.String(50), unique=True, nullable=False)

class ItemTag(db.Model):
    __tablename__ = 'item_tags'
    item_id = db.Column(db.Integer, db.ForeignKey('items.item_id'), primary_key=True)
    tag_id = db.Column(db.Integer, db.ForeignKey('tags.tag_id'), primary_key=True)
    item = db.relationship('Item')  
    tag = db.relationship('Tag') 

class ProductImage(db.Model):
    __tablename__ = 'product_images'
    image_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    item_id = db.Column(db.Integer, db.ForeignKey('items.item_id'), nullable=False)
    item = db.relationship('Item', backref=db.backref('images', lazy=True))
    image_url = db.Column(db.String(255), nullable=False) 
    is_main = db.Column(db.Boolean, nullable=False, default=False)

class ShoppingCart(db.Model):
    __tablename__ = 'shopping_carts'
    cart_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    user = db.relationship('User', backref=db.backref('shopping_cart', uselist=False))
    created_at = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

class CartItem(db.Model):
    __tablename__ = 'cart_items'
    cart_item_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    cart_id = db.Column(db.Integer, db.ForeignKey('shopping_carts.cart_id'), nullable=False)
    cart = db.relationship('ShoppingCart', backref=db.backref('items', lazy=True))
    item_id = db.Column(db.Integer, db.ForeignKey('items.item_id'), nullable=False)
    item = db.relationship('Item')
    quantity = db.Column(db.Integer, nullable=False)
    variation_id = db.Column(db.Integer, db.ForeignKey('item_variations.variation_id'))
    variation = db.relationship('ItemVariation')

    @property
    def total_price(self):
        return self.item.item_price * self.quantity

class Wishlist(db.Model):
    __tablename__ = 'wishlists'
    wishlist_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    user = db.relationship('User', backref=db.backref('wishlist', uselist=False))
    created_at = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

class WishlistItem(db.Model):
    __tablename__ = 'wishlist_items'
    wishlist_item_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    wishlist_id = db.Column(db.Integer, db.ForeignKey('wishlists.wishlist_id'), nullable=False)
    wishlist = db.relationship('Wishlist', backref=db.backref('items', lazy=True))
    item_id = db.Column(db.Integer, db.ForeignKey('items.item_id'), nullable=False)
    item = db.relationship('Item')
    variation_id = db.Column(db.Integer, db.ForeignKey('item_variations.variation_id'))
    variation = db.relationship('ItemVariation')

# models.py (updated Order class)
class Order(db.Model):
    __tablename__ = 'orders'
    order_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    user = db.relationship('User', backref=db.backref('orders', lazy=True))
    order_status = db.Column(db.String(50), nullable=False, default='pending')
    order_date = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp())
    shipping_address_id = db.Column(db.Integer, db.ForeignKey('addresses.address_id'), nullable=False)
    shipping_address = db.relationship('Address')
    total_amount = db.Column(db.Numeric(10, 2), nullable=False)
    stripe_payment_intent = db.Column(db.String(255))
    payment_method = db.Column(db.String(50), nullable=False, default='stripe')  
    payment_received = db.Column(db.Boolean, nullable=False, default=False) 
    refund_requested = db.Column(db.Boolean, default=False)
    refund_status = db.Column(db.String(50), nullable=True)
    refund_denial_reason = db.Column(db.Text, nullable=True)
    refund_reason = db.Column(db.Text, nullable=True)
    refund_processed_by = db.Column(db.Integer, db.ForeignKey('admins.admin_id'), nullable=True)

# class OrderItem(db.Model):
#     __tablename__ = 'order_items'
#     order_item_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     order_id = db.Column(db.Integer, db.ForeignKey('orders.order_id'), nullable=False)
#     order = db.relationship('Order', backref=db.backref('items', lazy=True))
#     item_id = db.Column(db.Integer, db.ForeignKey('items.item_id'), nullable=False)
#     item = db.relationship('Item')
#     quantity = db.Column(db.Integer, nullable=False)
#     variation_id = db.Column(db.Integer, db.ForeignKey('item_variations.variation_id'))
#     variation = db.relationship('ItemVariation')
#     price = db.Column(db.Numeric(10, 2), nullable=False)

class Messages(db.Model):
    __tablename__ = 'messages'
    message_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.order_id'), nullable=True)
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp())

class Review(db.Model):
    __tablename__ = 'reviews'
    review_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    item_id = db.Column(db.Integer, db.ForeignKey('items.item_id'), nullable=False)
    item = db.relationship('Item', backref=db.backref('reviews', lazy=True))
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    user = db.relationship('User', backref=db.backref('reviews', lazy=True))
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

class Discount(db.Model):
    __tablename__ = 'discounts'
    discount_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    discount_code = db.Column(db.String(50), unique=True, nullable=False)
    discount_type = db.Column(db.String(20), nullable=False)
    discount_value = db.Column(db.Numeric(10, 2), nullable=False)
    start_date = db.Column(db.TIMESTAMP, nullable=False)
    end_date = db.Column(db.TIMESTAMP, nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)

