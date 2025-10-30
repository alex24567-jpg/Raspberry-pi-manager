import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from pathlib import Path

def inspect(dbpath):
    print('Inspecting', dbpath)
    if not Path(dbpath).exists():
        print('  (not present)')
        return []
    conn = sqlite3.connect(dbpath)
    cur = conn.cursor()
    try:
        cur.execute('SELECT id, username, password_hash FROM user')
        rows = cur.fetchall()
        for r in rows:
            id, username, pw = r
            ok = check_password_hash(pw, 'TestPassword')
            print(f'  id={id} username={username!r} pw_hash={pw[:30]!s}... matches_TestPassword={ok}')
        return rows
    except Exception as e:
        print('  error reading user table:', e)
        return []
    finally:
        conn.close()


def set_password(dbpath, username='Admin', password='TestPassword'):
    print('Setting password on', dbpath)
    conn = sqlite3.connect(dbpath)
    cur = conn.cursor()
    try:
        cur.execute('SELECT id, username FROM user')
        rows = cur.fetchall()
        if not rows:
            print('  no users found; inserting Admin')
            pw_hash = generate_password_hash(password)
            cur.execute('INSERT INTO user (username, password_hash) VALUES (?, ?)', (username, pw_hash))
        else:
            for r in rows:
                cur.execute('UPDATE user SET password_hash=? WHERE id=?', (generate_password_hash(password), r[0]))
        conn.commit()
        print('  updated')
    except Exception as e:
        print('  error updating:', e)
    finally:
        conn.close()

if __name__ == '__main__':
    base = Path(__file__).parent
    db1 = str(base / 'rpm.db')
    db2 = str(base / 'instance' / 'rpm.db')
    print('\n-- BEFORE --')
    inspect(db1)
    inspect(db2)

    # if rpm.db doesn't match, update it
    rows = inspect(db1)
    matches = any(check_password_hash(r[2], 'TestPassword') for r in rows) if rows else False
    if not matches:
        print('\n-- fixing rpm.db --')
        set_password(db1)
        print('\n-- AFTER --')
        inspect(db1)
    else:
        print('\nrpm.db already matches')
