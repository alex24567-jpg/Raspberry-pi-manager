import os, sys
HERE = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, HERE)
from app import app, db, Device
import secrets

with app.app_context():
    # Drop and recreate all tables to ensure schema matches models (includes token column)
    print('Dropping all tables (if any)')
    db.drop_all()
    print('Creating tables')
    db.create_all()

    # create admin user bootstrap (app normally does this at import; ensure present)
    try:
        from app import User
        if User.query.count() == 0:
            u = User(username='Admin')
            u.set_password('TestPassword')
            db.session.add(u)
            db.session.commit()
            print('Bootstrapped Admin user')
    except Exception:
        pass

    # create Test device
    d = Device(id='Test')
    d.host = '127.0.0.1'
    d.username = None
    d.password = None
    d.port = 22
    d.token = secrets.token_urlsafe(24)
    db.session.merge(d)
    db.session.commit()
    print('Created device Test with token', d.token)
