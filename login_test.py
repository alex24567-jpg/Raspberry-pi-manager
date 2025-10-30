import requests

BASE = 'http://127.0.0.1:5000'
print('Posting to', BASE + '/login')
r = requests.post(BASE + '/login', data={'username':'Admin','password':'TestPassword'}, allow_redirects=False)
print('Status code:', r.status_code)
print('Headers:', r.headers.get('Location'))
print('Body snippet:', r.text[:800])
print('Cookies:', r.cookies.get_dict())
