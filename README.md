# SOUQKHANA E-Commerce Platform

SOUQKHANA is a full-featured e-commerce platform built with Flask, offering a comprehensive shopping experience with user authentication, product management, shopping cart, wishlist, and order processing capabilities.

Created as one of the prequisites to obtain a bachelor's degree in Computer Science

Computer Science Department, College of Computer Science & Information Technology, University of Kirkuk, Iraq
## Features

- User authentication and profile management
- Admin dashboard for product and order management
- Product browsing with category and tag filtering
- Shopping cart with real-time updates
- Wishlist functionality
- Secure checkout with Stripe integration
- Order tracking and management
- AI-powered shopping assistant
- Responsive design for all devices

## Prerequisites

- Python 3.8 or higher
- MySQL
- Stripe account for payment processing
- OpenRouter API key for AI assistant

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/v2kv/graduation.git
cd graduation
```

### 2. Create and activate a virtual environment

```bash
python -m venv venv
# On Windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Create SSL certificates for HTTPS

```bash
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

### 5. Create a `.env` file with the variable examples provided in .env.example file


### 6. Initialize the database

```bash
# With the virtual environment activated and app.py in your current directory
python app.py
```

This will create all the necessary tables in your MySQL database.

### 7. Run the application

```bash
flask run
```

The application will be available at https://localhost:5000

## Project Structure

```
.
├── app.py                   # Main application entry point
├── config.py                # Configuration settings
├── db.py                    # Database initialization
├── models.py                # Database models
├── routes/                  # Route handlers
│   ├── __init__.py
│   ├── admin_routes.py      # Admin dashboard routes
│   ├── cart_routes.py       # Shopping cart routes
│   ├── common.py            # Common imports and utilities
│   ├── index_routes.py      # Main page routes
│   ├── item_routes.py       # Product routes
│   ├── order_routes.py      # Order processing routes
│   ├── user_routes.py       # User authentication routes
│   └── wishlist_routes.py   # Wishlist routes
├── static/                  # Static assets
│   ├── css/
│   ├── js/
│   └── images/
└── templates/               # HTML templates
    ├── admin/               # Admin dashboard templates
    ├── emails/              # Email templates
    └── user/                # User account templates
```

## User Roles

### Admin
- Access admin dashboard
- Manage products and categories
- View and manage orders
- View user accounts

### Regular User
- Browse products
- Add items to cart and wishlist
- Place orders
- Track order status

## Development

### Adding a New Feature

1. Create or modify route handlers in the appropriate file in the `/routes` directory
2. Add any necessary models in `models.py`
3. Create or update templates in the `/templates` directory
4. Add static assets (CSS, JavaScript, etc.) in the `/static` directory

### Database Migrations

This project uses SQLAlchemy's `create_all()` for database initialization. For production environments, consider using a migration tool like Alembic.

## Security Notes

- HTTPS is enabled by default using self-signed certificates
- Passwords are hashed using Werkzeug's security functions
- Stripe is used for secure payment processing
- Flask-Login handles session management

## License

[MIT License](LICENSE)

## Contributors

- Ahmed Thabit Sultan, College of Computer Science, University of Kirkuk
- Ala Jassam Mohammed, College of Computer Science, University of Kirkuk
- Ala Younis Khalid, College of Computer Science, University of Kirkuk

## Acknowledgments

- Flask and its extensions
- Bootstrap for the frontend framework
- Stripe for payment processing
- OpenRouter for AI assistant capabilities