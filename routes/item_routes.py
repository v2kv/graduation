from routes.common import *

# Blueprint
item_bp = Blueprint('item', __name__)

@item_bp.route('/items')
def item_list():
    items = Item.query.options(joinedload(Item.images)).all()
    categories = Category.query.all()  # Add categories for filtering
    return render_template('item_list.html', items=items, categories=categories,show_footer=True)

@item_bp.route('/item/<int:item_id>')
def item_detail(item_id):
    item = Item.query.options(joinedload(Item.images)).get_or_404(item_id)
    print(f"DEBUG: Item details {item.__dict__}")  # Prints all attributes
    return render_template('item_detail.html', item=item,show_footer=True)