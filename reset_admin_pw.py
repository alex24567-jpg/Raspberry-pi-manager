from app import app, db, User
import os

NEW = os.environ.get('NEW_ADMIN_PW', 'TestPassword')

with app.app_context():
    user = User.query.filter(db.func.lower(User.username) == 'admin').first()
    if not user:
        user = User(username='Admin')
        db.session.add(user)
    user.set_password(NEW)
    db.session.commit()
    print('Set password for', user.username)
