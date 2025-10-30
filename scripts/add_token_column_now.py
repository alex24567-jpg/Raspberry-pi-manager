import sqlite3
DB='rpm.db'
conn=sqlite3.connect(DB)
cur=conn.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='device'")
if not cur.fetchone():
    print('NO_DEVICE_TABLE')
else:
    cur.execute('PRAGMA table_info(device)')
    cols=[r[1] for r in cur.fetchall()]
    print('COLUMNS:', cols)
    if 'token' not in cols:
        print('ADDING token column')
        cur.execute('ALTER TABLE device ADD COLUMN token BLOB')
        conn.commit()
        cur.execute('PRAGMA table_info(device)')
        print('NEW COLUMNS:', [r[1] for r in cur.fetchall()])
    else:
        print('token already present')
conn.close()
