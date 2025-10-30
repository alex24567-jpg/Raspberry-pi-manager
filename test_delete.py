import requests
BASE='http://127.0.0.1:5000'
s = requests.Session()
print('login...')
r = s.post(BASE+'/login', data={'username':'Admin','password':'TestPassword'}, allow_redirects=False)
print('login', r.status_code)
r = s.post(BASE+'/devices/delete', json={'ids':['smoke-1b']})
print('delete status', r.status_code)
print('body:', r.text)
print('headers:', r.headers)
