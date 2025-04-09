from routes.common import *

# Blueprint
item_bp = Blueprint('item', __name__)

@item_bp.route('/items')
def item_list():
    tag_id = request.args.get('tag_id', type=int)
    
    query = Item.query.options(joinedload(Item.images))
    
    if tag_id:
        tag = Tag.query.get_or_404(tag_id)
        query = query.join(ItemTag).filter(ItemTag.tag_id == tag_id)
    
    items = query.all()
    categories = Category.query.all()
    tags = Tag.query.all() 
    
    selected_tag = Tag.query.get(tag_id) if tag_id else None
    
    return render_template(
        'item_list.html', 
        items=items, 
        categories=categories,
        tags=tags,
        selected_tag=selected_tag,
        show_footer=True
    )

@item_bp.route('/item/<int:item_id>')
def item_detail(item_id):
    item = Item.query.options(joinedload(Item.images)).get_or_404(item_id)
    return render_template('item_detail.html', item=item,show_footer=True)