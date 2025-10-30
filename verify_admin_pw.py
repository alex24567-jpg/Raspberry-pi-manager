from app import app, db, User

with app.app_context():
    # try to find admin user case-insensitive
    u = User.query.filter(db.func.lower(User.username) == 'admin').first()
    if not u:
        print('NO_ADMIN_USER_FOUND')
    else:
        print('FOUND', u.username)
        try:
            ok = u.check_password('TestPassword')
            print('check TestPassword ->', ok)
        except Exception as e:
            print('check failed with exception:', e)
        try:
            ok2 = u.check_password('testpassword')
            print('check testpassword ->', ok2)
        except Exception as e:
            print('check failed with exception:', e)
        print('stored hash:', u.password_hash)
