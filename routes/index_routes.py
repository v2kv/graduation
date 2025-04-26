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

    items = Item.query.options(joinedload(Item.images)).all()
    
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

    all_subcategories = get_all_subcategories(selected_category)
    category_ids = [selected_category.category_id] + [sub.category_id for sub in all_subcategories]

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
        # Get ALL categories and items
        all_categories = Category.query.all()
        all_items = Item.query.all()
        
        # Prepare product information for the AI prompt
        product_info_text = ""
        if all_items:
            product_details = []
            # Include ALL products
            for item in all_items:
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
            product_info_text = "No products found in the database."
        
        # Prepare category information
        category_info = []
        
        # Include ALL categories
        if all_categories:
            category_names = [cat.category_name for cat in all_categories]
            category_info.append(f"Available categories: {', '.join(category_names)}")
        
        category_info_text = "\n".join(category_info) if category_info else "No categories found in the database."

        # Prepare the prompt for the AI
        prompt = f"""You are a friendly and helpful shopping assistant for the Souq Khana e-commerce platform.
        
        IMPORTANT INSTRUCTIONS:
        - Respond in a conversational, helpful tone like a retail assistant would.
        - Be brief but engaging - keep responses under 3 sentences when possible.
        - When mentioning prices, always include the dollar sign ($).
        - ONLY mention products or categories that are explicitly listed in the information below.
        - DO NOT make up any products or categories that aren't provided in the information.
        - Address customers directly using "you" and refer to the store as "we" or "Souq Khana".
        - For generic questions about what we sell, mention our main categories and highlight some popular products.
        - For budget questions, recommend products that fit within their budget.
        
        CRITICAL FORMAT INSTRUCTIONS:
        - NEVER respond with JSON format
        - ALWAYS respond with plain text
        - NEVER use code blocks or special formatting
        - DO NOT wrap your response in quotes or any other delimiters
        - Just provide a simple, direct conversational response
        
        Here is information about all products in our store:
        {product_info_text}
        
        Here is information about our product categories:
        {category_info_text}
        
        Customer question: {question}
        
        Remember to respond with PLAIN TEXT ONLY, not JSON or any other format."""

        # API call with the Llama 4 Maverick model
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
                    "model": "meta-llama/llama-4-maverick:free",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.7,
                    "max_tokens": 300,
                    "response_format": {"type": "text"} 
                },
                timeout=15 
            )
            
            # Check response status
            response.raise_for_status()
            
            # Parse JSON and get the answer with much better error handling
            try:
                response_data = response.json()
                
                if 'choices' in response_data and len(response_data['choices']) > 0:
                    answer = response_data['choices'][0]['message']['content']
                    
                    # Extensive cleanup to remove any JSON or markup
                    # Remove code blocks
                    answer = re.sub(r'```(?:json)?(.*?)```', r'\1', answer, flags=re.DOTALL)
                    
                    # Remove any JSON formatting attempts
                    answer = re.sub(r'^\s*\{\s*".*?"\s*:.*?\}.*?$', '', answer, flags=re.MULTILINE | re.DOTALL)
                    answer = re.sub(r'^\s*\[\s*\{.*?\}\s*\].*?$', '', answer, flags=re.MULTILINE | re.DOTALL)
                    
                    # Remove XML/HTML tags
                    answer = re.sub(r'<.*?>', '', answer)
                    
                    # Remove any trailing or leading quotes
                    answer = answer.strip('"\'')
                    
                    # Check if we have a valid response after cleanup
                    if not answer.strip():
                        return jsonify({'answer': "I'm sorry, I couldn't provide a specific response about our products. How else can I help you today?"}), 200
                    
                    return jsonify({'answer': answer}), 200
                else:
                    current_app.logger.error(f"Unexpected API response structure: {response_data}")
                    return jsonify({'answer': "I'm sorry, I'm having trouble understanding your question. Could you try asking in a different way?"}), 200
            
            except Exception as parse_error:
                current_app.logger.error(f"Failed to parse API response: {str(parse_error)}")
                # Try to get raw text as fallback
                try:
                    raw_text = response.text
                    # Attempt to extract anything that looks like a message
                    message_match = re.search(r'"content"\s*:\s*"([^"]+)"', raw_text)
                    if message_match:
                        return jsonify({'answer': message_match.group(1)}), 200
                    else:
                        return jsonify({'answer': "I apologize, but I'm having technical difficulties. Please try asking again later."}), 200
                except:
                    return jsonify({'answer': "I'm sorry, but our AI assistant is currently experiencing issues. Please try again later."}), 200
                
        except requests.exceptions.Timeout:
            current_app.logger.error("OpenRouter API timeout")
            return jsonify({'answer': "I'm sorry, our product assistant is taking longer than expected to respond. Please try again with a simpler question."}), 200
            
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"OpenRouter API Error: {str(e)}")
            return jsonify({'answer': "I'm sorry, our product assistant is currently unavailable. Please try again later."}), 200

    except Exception as e:
        current_app.logger.error(f"Unexpected error in ask_question: {str(e)}")
        return jsonify({'answer': "I'm sorry, I encountered an unexpected error. How else can I help you today?"}), 200