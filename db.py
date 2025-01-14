import os
from flask import current_app
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

db = SQLAlchemy()

def reset_auto_increment(db, table_name, primary_key='id'):
    max_id = db.session.query(text(f"MAX({primary_key}) FROM {table_name}")).scalar()
    if max_id is None:
        max_id = 0
    db.session.execute(text(f"ALTER TABLE {table_name} AUTO_INCREMENT = {max_id + 1}"))
    db.session.commit()

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_image(image, item_id):
    if image and allowed_file(image.filename):
        filename = secure_filename(image.filename)
        image_dir = os.path.join(current_app.root_path, 'static', 'uploads', str(item_id))
        os.makedirs(image_dir, exist_ok=True)
        image_path = os.path.join(image_dir, filename)
        image.save(image_path)
        return f'uploads/{item_id}/{filename}'
    return None

def delete_image(image_url):
    if image_url:
        image_path = os.path.join(current_app.root_path, 'static', image_url)
        if os.path.exists(image_path):
            os.remove(image_path)