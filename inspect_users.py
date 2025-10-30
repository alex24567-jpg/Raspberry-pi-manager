from app import app, db, User

with app.app_context():
    users = User.query.all()
    if not users:
        print('NO_USERS')
    for u in users:
        print('USER', u.id, u.username, u.password_hash)
