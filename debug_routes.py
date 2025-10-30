from app import app
import requests
print('URL map:')
for r in app.url_map.iter_rules():
    print(r)
BASE='http://127.0.0.1:5000'
print('\nGET /')
r=requests.get(BASE+'/')
print(r.status_code)
print('GET /devices/delete')
r=requests.get(BASE+'/devices/delete')
print(r.status_code)
print(r.text[:400])
