import requests
BASE='http://127.0.0.1:5000'
s = requests.Session()
print('login...')
r = s.post(BASE+'/login', data={'username':'Admin','password':'TestPassword'}, allow_redirects=False)
print('login status', r.status_code)
# fetch index and parse first device id
r = s.get(BASE+'/')
text = r.text
first = None
for line in text.splitlines():
    if '<strong>' in line and '</strong>' in line:
        a = line.strip()
        start = a.find('<strong>')+8
        end = a.find('</strong>')
        first = a[start:end]
        break
print('first device', first)
if first:
    r2 = s.post(f"{BASE}/devices/{first}/rename", json={'new_id': first+'-ren'})
    print('rename status', r2.status_code)
    print(r2.text)
