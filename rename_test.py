import requests
BASE='http://127.0.0.1:5000'
s = requests.Session()
print('login...')
r = s.post(BASE+'/login', data={'username':'Admin','password':'TestPassword'}, allow_redirects=False)
print('login', r.status_code)
# list devices
r = s.get(BASE+'/')
print('index ok', r.status_code)
# attempt rename of a device seen on the page; change 'smoke-1b' to an actual id if needed
old = 'smoke-1b'
print('rename', old)
r = s.post(f"{BASE}/devices/{old}/rename", json={'new_id': old+'-ren'}, allow_redirects=False)
print('status', r.status_code)
print(r.text)
