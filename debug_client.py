from app import app
with app.test_client() as c:
    print('POST /login with Admin/TestPassword')
    r = c.post('/login', data={'username':'Admin','password':'TestPassword'}, follow_redirects=False)
    print('status', r.status_code)
    print('headers', r.headers)
    print('data', r.get_data(as_text=True)[:400])

    print('\nPOST /devices/delete without login (should be 403)')
    r2 = c.post('/devices/delete', json={'ids':['smoke-1b']})
    print('status', r2.status_code)
    print('data', r2.get_data(as_text=True)[:400])

    print('\nNow login and try delete via test_client to preserve session:')
    r3 = c.post('/login', data={'username':'Admin','password':'TestPassword'}, follow_redirects=True)
    print('login follow status', r3.status_code)
    r4 = c.post('/devices/delete', json={'ids':['smoke-1b']})
    print('delete status after login', r4.status_code)
    print('delete data', r4.get_data(as_text=True)[:400])
