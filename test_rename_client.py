from app import app

with app.test_client() as c:
    # login
    r = c.post('/login', data={'username':'Admin','password':'TestPassword'}, follow_redirects=True)
    print('login status', r.status_code)
    # pick first device from index
    r = c.get('/')
    text = r.get_data(as_text=True)
    first = None
    for line in text.splitlines():
        if '<strong>' in line and '</strong>' in line:
            a = line.strip(); first = a[a.find('<strong>')+8:a.find('</strong>')]; break
    print('first device', first)
    if first:
        r2 = c.post(f'/devices/{first}/rename', json={'new_id': first+'-ren'})
        print('rename status', r2.status_code)
        print('data', r2.get_data(as_text=True)[:1000])
