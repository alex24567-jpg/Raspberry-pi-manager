import os
import sys
import time
import json

import requests

BASE = os.environ.get('SMOKE_BASE', 'http://127.0.0.1:5000')
ADMIN_PW = os.environ.get('RPM_ADMIN_PW', 'admin')

s = requests.Session()

def fail(msg):
    print('FAIL:', msg)
    sys.exit(2)

print('Waiting for server...')
for _ in range(10):
    try:
        r = s.get(BASE + '/')
        if r.status_code == 200:
            break
    except Exception:
        pass
    time.sleep(0.5)
else:
    fail('Server not responding at ' + BASE)

print('Logging in...')
r = s.post(BASE + '/login', data={'password': ADMIN_PW}, allow_redirects=False)
if r.status_code not in (200,302):
    fail('Login failed: status '+str(r.status_code))
print('Logged in')

# add device
dev = {'id':'smoke-1','host':'127.0.0.1','username':'pi','password':'rasp','port':22}
print('Adding device:', dev['id'])
r = s.post(BASE + '/devices', json=dev)
if r.status_code != 200:
    fail('/devices POST failed: '+r.text)
print('Added')

# rename device
print('Renaming device smoke-1 -> smoke-1b')
r = s.post(BASE + '/devices/smoke-1/rename', json={'new_id':'smoke-1b'})
if r.status_code != 200:
    fail('rename failed: '+r.text)
print('Renamed')

# save policy
print('Saving policy')
policy = {'name':'smoke-policy','content':'#!/bin/bash\necho smoke'}
r = s.post(BASE + '/policies', json=policy)
if r.status_code != 200:
    fail('save policy failed: '+r.text)
pid = r.json().get('policy',{}).get('id')
if not pid:
    fail('no policy id returned')
print('Saved policy id', pid)

# list policies
print('Listing policies')
r = s.get(BASE + '/policies')
if r.status_code != 200:
    fail('list policies failed: '+r.text)
print('Policies:', r.json())

print('SMOKE TEST PASSED')
sys.exit(0)
