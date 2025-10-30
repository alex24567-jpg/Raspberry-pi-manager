import requests
BASE='http://127.0.0.1:5000'
print('getting index...')
r = requests.get(BASE+'/')
print('status', r.status_code)
text = r.text
# crude parse: find lines with device ids
ids = []
for line in text.splitlines():
    if '<strong>' in line and '</strong>' in line:
        a = line.strip()
        start = a.find('<strong>')+8
        end = a.find('</strong>')
        ids.append(a[start:end])
print('ids found:', ids)
