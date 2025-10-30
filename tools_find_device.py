from app import Device, db, app
with app.app_context():
    rows = Device.query.all()
    if not rows:
        print('No devices in DB')
    else:
        for d in rows:
            print('ID:', d.id)
            print('  host:', d.host)
            print('  username:', d.username)
            print('  port:', d.port)
            print('  token:', '[set]' if d.token else '[none]')
            print('')
