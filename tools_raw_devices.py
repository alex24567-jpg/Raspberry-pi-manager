import sqlite3
import os
p='rpm.db'
if not os.path.exists(p):
    print('rpm.db not found in cwd')
    raise SystemExit(1)
con=sqlite3.connect(p)
cur=con.cursor()
# list columns
cur.execute("PRAGMA table_info(device)")
cols=cur.fetchall()
print('device table columns:')
for c in cols:
    print(' ', c)
# try to select common cols
try:
    cur.execute('SELECT id, host, username, port FROM device')
    rows=cur.fetchall()
    if not rows:
        print('no device rows')
    for r in rows:
        print('ID:', r[0])
        print(' host raw:', r[1])
        print(' username raw:', r[2])
        print(' port:', r[3])
        print('')
except Exception as e:
    print('select failed:', e)
    # try a more generic select
    try:
        cur.execute('SELECT id FROM device')
        for r in cur.fetchall():
            print('ID:', r[0])
    except Exception as e2:
        print('failed to read device table:', e2)
con.close()
