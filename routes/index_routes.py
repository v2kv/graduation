from routes.common import *

# Blueprint
index_bp = Blueprint('index', __name__)

@index_bp.route('/')
def index():
    categories = Category.query.all()

    category_tree = {}
    for category in categories:
        parent_id = category.parent_category_id or 0 
        if parent_id not in category_tree:
            category_tree[parent_id] = []
        category_tree[parent_id].append(category)

    items = Item.query.options(joinedload(Item.images)).order_by(Item.item_name.asc()).all()
    
    tags = Tag.query.all()

    cart_count = 0
    wishlist_count = 0
    orders_count = 0
    unread_messages_count = 0
    if current_user.is_authenticated and current_user.role != "admin":
        cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
        cart_count = sum(item.quantity for item in cart.items) if cart else 0

        wishlist = Wishlist.query.filter_by(user_id=current_user.user_id).first()
        wishlist_count = len(wishlist.items) if wishlist else 0

        orders_count = Order.query.filter_by(user_id=current_user.user_id).filter(
            ~Order.order_status.in_(['delivered', 'cancelled'])
        ).count()

        unread_messages_count = Messages.query.filter_by(user_id=current_user.user_id, is_read=False).count()

    return render_template(
        'index.html',
        items=items,
        category_tree=category_tree, 
        cart_count=cart_count,
        wishlist_count=wishlist_count,
        orders_count=orders_count,
        unread_messages_count=unread_messages_count,
        show_footer=True,
        tags=tags 
    )

# API to get the counts dynamically
@index_bp.route('/api/counters')
@login_required
def get_counters():
    if current_user.is_authenticated and current_user.role != "admin":
        cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
        wishlist = Wishlist.query.filter_by(user_id=current_user.user_id).first()
        no_of_users=db.session.query(User).count()
        unread_messages_count = Messages.query.filter_by(user_id=current_user.user_id, is_read=False).count()
        orders_count = Order.query.filter_by(user_id=current_user.user_id).filter(
            ~Order.order_status.in_(['delivered', 'cancelled'])
        ).count()

        return jsonify({
            'cart_count': sum(item.quantity for item in cart.items) if cart else 0,
            'wishlist_count': len(wishlist.items) if wishlist else 0,
            'orders_count': orders_count,
            'unread_messages_count': unread_messages_count
        })
    return None

# Inject counts into the global context to make them available in all templates
@index_bp.app_context_processor
def inject_counts():
    if current_user.is_authenticated and current_user.role != "admin":
        cart = ShoppingCart.query.filter_by(user_id=current_user.user_id).first()
        wishlist = Wishlist.query.filter_by(user_id=current_user.user_id).first()
        
        unread_messages_count = Messages.query.filter_by(user_id=current_user.user_id, is_read=False).count()
        orders_count = Order.query.filter_by(user_id=current_user.user_id).filter(
            ~Order.order_status.in_(['delivered', 'cancelled'])
        ).count()

        return {
            'cart_count': sum(item.quantity for item in cart.items) if cart else 0,
            'wishlist_count': len(wishlist.items) if wishlist else 0,
            'orders_count': orders_count,
            'unread_messages_count': unread_messages_count
        }

    cate=Category.query.count();
    NoOfUsers=User.query.count();
    NoOfItems=Item.query.count();
    NoOfTag=Tag.query.count();
    NoOfOrder=Order.query.count();
    return {
        'cart_count': 0,
        'wishlist_count': 0,
        'orders_count': 0,
        'unread_messages_count': 0,
        'NoOfUsers': NoOfUsers,
        'NoOfItems': NoOfItems,
        'NoOfTag': NoOfTag,
        'NoOfOrder': NoOfOrder,
        'cate':cate
    }


@index_bp.route('/category/<category_slug>')
def filter_by_category(category_slug):
    """Filter items based on category slug."""
    category_slug = category_slug.lower() 

    selected_category = next(
        (c for c in Category.query.all() if generate_slug(c.category_name) == category_slug),
        None
    )

    if not selected_category:
        print("Category not found!") 
        return "Category not found", 404

    # ✅ Fetch subcategories
    all_subcategories = get_all_subcategories(selected_category)
    category_ids = [selected_category.category_id] + [sub.category_id for sub in all_subcategories]

    # ✅ Fetch items belonging to this category or subcategories
    items = Item.query.filter(Item.category_id.in_(category_ids)).options(joinedload(Item.images)).all()

    return render_template('category.html', items=items, category=selected_category, show_footer=True)

@index_bp.route('/filter', methods=['POST'])
def filter_items():
    """Handle the category and tag filtering via AJAX."""
    category_id = request.json.get('category_id')
    tag_id = request.json.get('tag_id')
    
    query = Item.query.options(joinedload(Item.images))
    
    if category_id:
        selected_category = Category.query.get(category_id)
        if selected_category:
            all_subcategories = get_all_subcategories(selected_category)
            category_ids = [selected_category.category_id] + [sub.category_id for sub in all_subcategories]
            query = query.filter(Item.category_id.in_(category_ids))
    
    if tag_id:
        query = query.join(ItemTag).filter(ItemTag.tag_id == tag_id)
    
    items = query.all()

    return jsonify([
        {
            'id': item.item_id,
            'name': item.item_name,
            'price': str(item.item_price),
            'description': item.item_description,
            'image_url': item.images[0].image_url if item.images else None,
            'tags': [{'id': tag.tag_id, 'name': tag.tag_name} for tag in item.tags]
        }
        for item in items
    ])

@index_bp.route('/ask', methods=['POST'])
def ask_question():
    data = request.get_json()
    question = data.get('question', '')
    
    if not question:
        return jsonify({'error': 'No question provided'}), 400
    
    try:
        # Detect if this is a generic question about what we sell
        generic_questions = [
            'what do you sell', 'what products do you have', 'what can i buy', 
            'what is available', 'what do you offer', 'show me products',
            'what items', 'list products', 'what categories'
        ]
        is_generic_question = any(gen_q in question.lower() for gen_q in generic_questions)
        
        # Get database information based on the question
        try:
            all_categories = Category.query.all()
            
            # Prepare items to search based on question type
            items = []
            
            if is_generic_question:
                # For generic questions, get a sampling of products across categories
                # This ensures we have something to show even for broad questions
                for category in all_categories:
                    # Get up to 2 items from each category for a good representative sample
                    category_items = Item.query.filter_by(category_id=category.category_id).limit(2).all()
                    items.extend(category_items)
            else:
                # For specific questions, perform keyword search
                keywords = [word.strip() for word in question.lower().split() if len(word.strip()) > 2]
                
                # Build filters for each keyword
                item_filters = []
                for keyword in keywords:
                    item_filters.append(Item.item_name.ilike(f'%{keyword}%'))
                    if hasattr(Item, 'item_description'):
                        item_filters.append(Item.item_description.ilike(f'%{keyword}%'))
                
                # Apply filters if we have any
                if item_filters:
                    items = Item.query.filter(or_(*item_filters)).all()
                    
                    # Log what was found for debugging
                    current_app.logger.info(f"Search for '{question}' found {len(items)} items")
                    for item in items[:3]:
                        current_app.logger.info(f"Match: {item.item_name} (${item.item_price})")
                
                # If no items found with keywords, try to find matching categories
                if not items and keywords:
                    category_filters = []
                    for keyword in keywords:
                        category_filters.append(Category.category_name.ilike(f'%{keyword}%'))
                    
                    if category_filters:
                        matching_categories = Category.query.filter(or_(*category_filters)).all()
                        
                        # Get items from matching categories
                        for category in matching_categories:
                            category_items = Item.query.filter_by(category_id=category.category_id).limit(5).all()
                            items.extend(category_items)
            
        except Exception as db_error:
            current_app.logger.error(f"Database error: {str(db_error)}")
            return jsonify({'error': 'Unable to search products. Please try again.'}), 500
        
        # Prepare product information for the AI prompt
        product_info_text = ""
        if items:
            product_details = []
            for item in items[:8]:  # Limit to 8 items 
                detail = f"Product: {item.item_name}, Price: ${item.item_price}"
                if hasattr(item, 'item_description') and item.item_description:
                    # Add description if available and not empty
                    description = item.item_description.strip()
                    if description:
                        detail += f", Description: {description[:100]}"
                        if len(description) > 100:
                            detail += "..."
                
                # Add category if available
                if hasattr(item, 'category') and item.category:
                    detail += f", Category: {item.category.category_name}"
                
                product_details.append(detail)
            
            product_info_text = "\n".join(product_details)
        else:
            product_info_text = "No specific products found matching the query."
        
        # Prepare category information
        category_info = []
        
        # For all questions, include available categories
        if all_categories:
            category_names = [cat.category_name for cat in all_categories]
            category_info.append(f"Available categories: {', '.join(category_names)}")
        
        # For generic questions or if no specific products found, add sample items per category
        if is_generic_question or not items:
            for category in all_categories:
                sample_items = Item.query.filter_by(category_id=category.category_id).limit(3).all()
                if sample_items:
                    item_names = [item.item_name for item in sample_items]
                    category_info.append(f"Category '{category.category_name}' includes: {', '.join(item_names)}")
        
        category_info_text = "\n".join(category_info) if category_info else "No categories found in the database."

        # Prepare the prompt for the AI
        prompt = f"""You are a friendly and helpful shopping assistant for the Souq Khana e-commerce platform.
        
        IMPORTANT INSTRUCTIONS:
        - Respond in a conversational, helpful tone like a retail assistant would.
        - Be brief but engaging - keep responses under 3 sentences when possible.
        - NEVER use any kind of Markdown formatting in your responses.
        - Format your response as plain text only.
        - When mentioning prices, always include the dollar sign ($).
        - ONLY mention products or categories that are explicitly listed in the information below.
        - DO NOT make up any products or categories that aren't provided in the information.
        - If the product information section says "No specific products found", clearly state we don't currently have that item.
        - Address customers directly using "you" and refer to the store as "we" or "Souq Khana".
        - For generic questions about what we sell, mention our main categories and highlight some popular products.
        
        Here is information about products that might match the customer's query:
        {product_info_text}
        
        Here is information about our product categories:
        {category_info_text}
        
        Customer question: {question}"""

        # API call with timeout and error handling
        try:
            response = requests.post(
                url="https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {current_app.config['OPENROUTER_API_KEY']}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": request.host_url,
                    "X-Title": "Souq Khana"
                },
                json={
                    "model": "deepseek/deepseek-r1-zero:free",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.7,
                    "max_tokens": 300
                },
                timeout=15 
            )
            
            # Check response status
            response.raise_for_status()
            
            # Parse JSON and get the answer
            response_data = response.json()
            if 'choices' in response_data and len(response_data['choices']) > 0:
                answer = response_data['choices'][0]['message']['content']
                
                # Clean up answer - remove unwanted formatting
                answer = answer.replace('\\boxed{', '')
                answer = answer.replace('}', '')
                answer = answer.replace('```', '')
                
                # check we're not returning empty responses
                if not answer.strip():
                    # Generate a basic fallback response using actual database content
                    fallback = "I'm sorry, I couldn't generate a specific response. "
                    
                    if all_categories:
                        category_names = [cat.category_name for cat in all_categories]
                        fallback += f"At Souq Khana, we offer products in these categories: {', '.join(category_names)}. "
                    
                    if items:
                        fallback += f"Some of our products include {', '.join([item.item_name for item in items[:5]])}. "
                        
                    fallback += "How can I help you find something specific today?"
                    return jsonify({'answer': fallback}), 200
                    
                return jsonify({'answer': answer}), 200
            else:
                current_app.logger.error(f"Unexpected API response structure: {response_data}")
                return jsonify({'error': 'Invalid response from AI service'}), 500
                
        except requests.exceptions.Timeout:
            current_app.logger.error("OpenRouter API timeout")
            return jsonify({'error': 'The service is taking too long to respond. Please try again later.'}), 504
            
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"OpenRouter API Error: {str(e)}")
            return jsonify({'error': 'Our product assistant is currently unavailable. Please try again later.'}), 503

    except Exception as e:
        current_app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred. Please try again later.'}), 500