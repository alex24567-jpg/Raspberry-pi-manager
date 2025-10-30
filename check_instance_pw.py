from werkzeug.security import check_password_hash
import sqlite3
DB = r"c:\Users\ahinkley.AXIUM\Code\raspberry-pi-manager\instance\rpm.db"
conn = sqlite3.connect(DB)
c = conn.cursor()
c.execute('SELECT id, username, password_hash from user')
rows = c.fetchall()
for r in rows:
    print(r[0], r[1], check_password_hash(r[2],'TestPassword'))
conn.close()
