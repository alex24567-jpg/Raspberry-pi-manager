import os
import sys
HERE = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, HERE)

from app import app, db, Device
import secrets

d = Device(id='Test')
d.host = '127.0.0.1'
d.username = None
d.password = None
d.port = 22
d.token = secrets.token_urlsafe(24)

# merge in case exists
with app.app_context():
	# Ensure tables exist (in case DB was just created)
	db.create_all()
	db.session.merge(d)
	db.session.commit()
	print('created device', d.id, 'token=', d.token)
