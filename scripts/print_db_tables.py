import sqlite3
conn=sqlite3.connect('rpm.db')
cur=conn.cursor()
cur.execute("SELECT name, sql FROM sqlite_master WHERE type='table'")
rows=cur.fetchall()
print('TABLE COUNT', len(rows))
for r in rows:
    print('---')
    print('TABLE:', r[0])
    print(r[1])
cur.close()
conn.close()
