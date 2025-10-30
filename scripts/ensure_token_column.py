import sqlite3
import sys

DB='rpm.db'
try:
    conn=sqlite3.connect(DB)
    cur=conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='device'")
    if not cur.fetchone():
        print('NO_DEVICE_TABLE')
        sys.exit(0)
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
except Exception as e:
    print('ERR', e)
finally:
    try:
        conn.close()
    except:
        pass
