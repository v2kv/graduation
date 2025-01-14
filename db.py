from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

db = SQLAlchemy()

def reset_auto_increment(db, table_name, primary_key='id'):
    max_id = db.session.query(text(f"MAX({primary_key}) FROM {table_name}")).scalar()
    if max_id is None:
        max_id = 0
    db.session.execute(text(f"ALTER TABLE {table_name} AUTO_INCREMENT = {max_id + 1}"))
    db.session.commit()