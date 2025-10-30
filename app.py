from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from ssh_client import SSHClientManager
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import secrets
from cryptography.fernet import Fernet, InvalidToken

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('RPM_SECRET', 'dev-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rpm.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
ssh_mgr = SSHClientManager()
executor = ThreadPoolExecutor(max_workers=10)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Setup Fernet encryption (optional). Provide RPM_FERNET_KEY in environment to enable.
FERNET_KEY = os.environ.get('RPM_FERNET_KEY')
FERNET = Fernet(FERNET_KEY) if FERNET_KEY else None

class Device(db.Model):
    id = db.Column(db.String, primary_key=True)
    _host = db.Column('host', db.LargeBinary, nullable=False)
    _username = db.Column('username', db.LargeBinary)
    _password = db.Column('password', db.LargeBinary)
    _token = db.Column('token', db.LargeBinary)
    port = db.Column(db.Integer, default=22)

    # transparent encrypted properties
    @property
    def host(self):
        if not self._host:
            return None
        # handle cases where the column contains text (legacy) or bytes
        if isinstance(self._host, str):
            return self._host
        if isinstance(self._host, (bytes, bytearray)):
            if FERNET:
                try:
                    return FERNET.decrypt(self._host).decode('utf-8')
                except InvalidToken:
                    return None
            return self._host.decode('utf-8')
        # unknown type
        return None

    @host.setter
    def host(self, v):
        if v is None:
            self._host = None
            return
        b = v.encode('utf-8')
        self._host = FERNET.encrypt(b) if FERNET else b

    @property
    def username(self):
        if not self._username:
            return None
        if isinstance(self._username, str):
            return self._username
        if isinstance(self._username, (bytes, bytearray)):
            if FERNET:
                try:
                    return FERNET.decrypt(self._username).decode('utf-8')
                except InvalidToken:
                    return None
            return self._username.decode('utf-8')
        return None

    @username.setter
    def username(self, v):
        if v is None:
            self._username = None
            return
        b = v.encode('utf-8')
        self._username = FERNET.encrypt(b) if FERNET else b

    @property
    def password(self):
        if not self._password:
            return None
        if isinstance(self._password, str):
            return self._password
        if isinstance(self._password, (bytes, bytearray)):
            if FERNET:
                try:
                    return FERNET.decrypt(self._password).decode('utf-8')
                except InvalidToken:
                    return None
            return self._password.decode('utf-8')
        return None

    @password.setter
    def password(self, v):
        if v is None:
            self._password = None
            return
        b = v.encode('utf-8')
        self._password = FERNET.encrypt(b) if FERNET else b

    @property
    def token(self):
        if not self._token:
            return None
        if isinstance(self._token, str):
            return self._token
        if isinstance(self._token, (bytes, bytearray)):
            if FERNET:
                try:
                    return FERNET.decrypt(self._token).decode('utf-8')
                except InvalidToken:
                    return None
            return self._token.decode('utf-8')
        return None

    @token.setter
    def token(self, v):
        if v is None:
            self._token = None
            return
        b = v.encode('utf-8')
        self._token = FERNET.encrypt(b) if FERNET else b

class Deployment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String, db.ForeignKey('device.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean)
    output = db.Column(db.Text)


class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String, db.ForeignKey('device.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    severity = db.Column(db.String)
    summary = db.Column(db.String)
    details = db.Column(db.Text)


class Policy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    content = db.Column(db.Text, nullable=False)
    created = db.Column(db.DateTime, default=datetime.utcnow)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.String, nullable=False)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

with app.app_context():
    db.create_all()
    # Ensure 'token' column exists in the device table (SQLite will allow ALTER TABLE ADD COLUMN)
    try:
        res = db.session.execute("PRAGMA table_info(device)").fetchall()
        cols = [r[1] for r in res]
        if 'token' not in cols:
            # add token column as BLOB
            db.session.execute("ALTER TABLE device ADD COLUMN token BLOB")
            db.session.commit()
    except Exception:
        # non-fatal if PRAGMA/ALTER fails on some DBs; column may already exist
        app.logger.debug('PRAGMA/ALTER for token column skipped or failed')
    # bootstrap a default admin user if no users exist
    # Default credentials: username 'Admin', password 'TestPassword'
    if User.query.count() == 0:
        u = User(username='Admin')
        u.set_password('TestPassword')
        db.session.add(u)
        db.session.commit()
        print("Bootstrapped default admin user 'Admin' with password 'TestPassword'")

def is_logged_in():
    return current_user.is_authenticated

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or 'Admin').strip()
        pw = request.form.get('password')
        try:
            app.logger.debug('/login POST username=%s form_keys=%s', username, list(request.form.keys()))
        except Exception:
            app.logger.exception('error reading login form')
        # case-insensitive lookup
        user = User.query.filter(db.func.lower(User.username) == username.lower()).first()
        if user:
            try:
                ok = user.check_password(pw)
            except Exception:
                ok = False
                app.logger.exception('error checking password for %s', username)
            app.logger.debug('user found: %s password_ok=%s', user.username, ok)
        else:
            app.logger.debug('user not found: %s', username)

        if user and user.check_password(pw):
            login_user(user)
            app.logger.info('user logged in: %s', user.username)
            return redirect(url_for('index'))
        flash('Bad username or password', 'error')
        return render_template('login.html')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/')
def index():
    devices = Device.query.all()
    deployments = Deployment.query.order_by(Deployment.timestamp.desc()).limit(50).all()
    return render_template('index.html', devices=devices, deployments=deployments, logged_in=is_logged_in())

@app.route('/devices', methods=['POST'])
def add_device():
    if not is_logged_in():
        return jsonify({'status': 'error', 'message': 'unauthorized'}), 403
    data = request.json or {}
    # required id and host
    if not data.get('id') or not data.get('host'):
        return jsonify({'status': 'error', 'message': 'missing id or host'}), 400

    # parse port robustly: accept int, string numeric, or default to 22
    port_val = data.get('port', None)
    if port_val in (None, ''):
        port = 22
    else:
        try:
            port = int(port_val)
        except (ValueError, TypeError):
            return jsonify({'status': 'error', 'message': 'invalid port'}), 400

    # preserve existing token if merging an existing device
    existing = Device.query.get(data['id'])
    d = Device(id=data['id'], port=port)
    d.host = data['host']
    d.username = data.get('username')
    d.password = data.get('password')
    if existing and existing.token:
        d.token = existing.token
    else:
        # generate a device token for authenticating audit posts
        tok = secrets.token_urlsafe(24)
        d.token = tok
        # include token in response so admin can provision device
        data = dict(data)
        data['_token'] = tok
    db.session.merge(d)
    db.session.commit()
    return jsonify({'status': 'ok', 'device': data})


@app.route('/devices/add', methods=['GET'])
def devices_add_form():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('devices_add.html', logged_in=is_logged_in())


@app.route('/devices/<old_id>/rename', methods=['POST'])
def rename_device(old_id):
    if not is_logged_in():
        return jsonify({'status': 'error', 'message': 'unauthorized'}), 403

    try:
        payload = request.json
        app.logger.debug('rename payload: %s', payload)
        new_id = payload.get('new_id')
        if not new_id:
            return jsonify({'status': 'error', 'message': 'missing new_id'}), 400
        if Device.query.get(new_id):
            return jsonify({'status': 'error', 'message': 'new id already exists'}), 400

        d = Device.query.get(old_id)
        if not d:
            app.logger.debug('device %s not found', old_id)
            return jsonify({'status': 'error', 'message': 'device not found'}), 404

        app.logger.info('renaming device: old_id=%s new_id=%s', old_id, new_id)

        new = Device(id=new_id, port=getattr(d, 'port', None))

        def _normalize(val):
            if val is None:
                return None
            if isinstance(val, (bytes, bytearray, memoryview)):
                return bytes(val)
            if isinstance(val, str):
                b = val.encode('utf-8')
                return FERNET.encrypt(b) if FERNET else b
            try:
                s = str(val)
                b = s.encode('utf-8')
                return FERNET.encrypt(b) if FERNET else b
            except Exception:
                return None

        try:
            new._host = _normalize(d._host)
            new._username = _normalize(d._username)
            new._password = _normalize(d._password)
        except Exception:
            app.logger.exception('error normalizing underlying fields from device %s', old_id)
            raise

        db.session.add(new)
        # update deployments to point to new id
        Deployment.query.filter_by(device_id=old_id).update({'device_id': new_id})
        # remove old device
        db.session.delete(d)
        db.session.commit()
        return jsonify({'status': 'ok', 'old_id': old_id, 'new_id': new_id})
    except Exception as e:
        app.logger.exception('rename_device exception for %s -> %s', old_id, payload.get('new_id') if payload else None)
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/devices/delete', methods=['POST'])
def delete_devices():
    # debug: log incoming request for diagnostics
    try:
        app.logger.debug('/devices/delete called from %s method=%s', request.remote_addr, request.method)
        app.logger.debug('headers: %s', dict(request.headers))
        app.logger.debug('raw_data: %s', request.get_data())
    except Exception:
        app.logger.exception('error logging request')

    if not is_logged_in():
        app.logger.warning('unauthorized delete attempt from %s', request.remote_addr)
        return jsonify({'status': 'error', 'message': 'unauthorized'}), 403
    data = request.json
    ids = data.get('ids') or []
    if not ids:
        return jsonify({'status':'error','message':'no ids'}), 400
    # delete deployments and devices
    for did in ids:
        Deployment.query.filter_by(device_id=did).delete()
        Device.query.filter_by(id=did).delete()
    db.session.commit()
    return jsonify({'status':'ok','deleted': ids})

@app.route('/deploy', methods=['POST'])
def deploy():
    if not is_logged_in():
        return jsonify({'status': 'error', 'message': 'unauthorized'}), 403
    payload = request.json
    target_ids = payload.get('targets', [])
    policy = payload.get('policy', '')
    policy_id = payload.get('policy_id')

    # if a saved policy id is provided, load it
    if policy_id:
        p = Policy.query.get(policy_id)
        if p:
            policy = p.content
        else:
            return jsonify({'status': 'error', 'message': 'Policy not found'}), 400

    if not target_ids:
        targets = Device.query.all()
    else:
        targets = Device.query.filter(Device.id.in_(target_ids)).all()

    if not targets:
        return jsonify({'status': 'error', 'message': 'No targets found'}), 400

    app.logger.info('deploy: submitting policy to %d targets', len(targets))
    # submit tasks
    futures = {executor.submit(ssh_mgr.push_policy, {'id': d.id, 'host': d.host, 'username': d.username, 'password': d.password, 'port': d.port}, policy): d for d in targets}
    results = []
    for fut in as_completed(futures):
        target = futures[fut]
        app.logger.info('deploy: waiting for result for %s', target.id)
        try:
            res = fut.result()
            success = True
            output = res
            app.logger.info('deploy: success for %s', target.id)
        except Exception as e:
            success = False
            output = str(e)
            app.logger.warning('deploy: failure for %s error=%s', target.id, output)

        # record deployment
        rec = Deployment(device_id=target.id, success=success, output=output)
        db.session.add(rec)
        db.session.commit()

        results.append({'target': target.id, 'success': success, 'output': output})

    return jsonify({'status': 'ok', 'results': results})

@app.route('/deployments')
def list_deployments():
    if not is_logged_in():
        return jsonify({'status': 'error', 'message': 'unauthorized'}), 403
    rows = Deployment.query.order_by(Deployment.timestamp.desc()).limit(200).all()
    out = [{'device_id': r.device_id, 'timestamp': r.timestamp.isoformat(), 'success': r.success, 'output': r.output} for r in rows]
    return jsonify({'deployments': out})


@app.route('/policies', methods=['GET', 'POST'])
def policies():
    if not is_logged_in():
        return jsonify({'status': 'error', 'message': 'unauthorized'}), 403
    if request.method == 'GET':
        rows = Policy.query.order_by(Policy.created.desc()).all()
        out = [{'id': r.id, 'name': r.name, 'created': r.created.isoformat()} for r in rows]
        return jsonify({'policies': out})
    else:
        data = request.json
        name = data.get('name') or 'unnamed'
        content = data.get('content', '')
        if not content:
            return jsonify({'status': 'error', 'message': 'Empty policy'}), 400
        p = Policy(name=name, content=content)
        db.session.add(p)
        db.session.commit()
        return jsonify({'status': 'ok', 'policy': {'id': p.id, 'name': p.name}})


@app.route('/policies/<int:policy_id>', methods=['GET', 'DELETE'])
def policy_detail(policy_id):
    if not is_logged_in():
        return jsonify({'status': 'error', 'message': 'unauthorized'}), 403
    p = Policy.query.get(policy_id)
    if not p:
        return jsonify({'status': 'error', 'message': 'not found'}), 404
    if request.method == 'GET':
        return jsonify({'id': p.id, 'name': p.name, 'content': p.content, 'created': p.created.isoformat()})
    else:
        db.session.delete(p)
        db.session.commit()
        return jsonify({'status': 'ok'})


@app.route('/account/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form.get('current')
        new = request.form.get('new')
        confirm = request.form.get('confirm')
        if not current or not new or new != confirm:
            flash('Invalid input', 'error')
            return render_template('change_password.html')
        user = current_user
        if not user.check_password(current):
            flash('Current password incorrect', 'error')
            return render_template('change_password.html')
        user.set_password(new)
        db.session.commit()
        flash('Password changed', 'success')
        return redirect(url_for('index'))
    return render_template('change_password.html')

@app.route('/devices/<device_id>/top')
@login_required
def device_top(device_id):
    """Run a one-shot 'top' command over SSH against the device and return plain text output."""
    d = Device.query.get(device_id)
    if not d:
        return jsonify({'status':'error','message':'device not found'}), 404
    device = {'id': d.id, 'host': d.host, 'username': d.username, 'password': d.password, 'port': d.port}
    try:
        out = ssh_mgr.run_command(device, 'top -b -n 1', timeout=20)
    except Exception as e:
        app.logger.exception('device_top error for %s', device_id)
        # fallback to ps listing
        try:
            out = ssh_mgr.run_command(device, 'ps aux --sort=-%cpu | head -n 20', timeout=20)
        except Exception as e2:
            app.logger.exception('fallback ps failed for %s', device_id)
            return jsonify({'status':'error','message':str(e2)}), 500
    return app.response_class(out, mimetype='text/plain')


@app.route('/devices/<device_id>/audits', methods=['POST'])
def receive_audit(device_id):
    """Endpoint for devices to POST security audit results.
    Devices must include header 'X-Device-Token' with their token.
    """
    d = Device.query.get(device_id)
    if not d:
        return jsonify({'status':'error','message':'device not found'}), 404
    token = request.headers.get('X-Device-Token') or request.args.get('token')
    if not token or token != d.token:
        app.logger.warning('unauthorized audit post for %s from %s', device_id, request.remote_addr)
        return jsonify({'status':'error','message':'unauthorized'}), 403
    data = request.json or {}
    severity = data.get('severity') or 'info'
    summary = data.get('summary') or data.get('title') or 'security audit'
    details = data.get('details') or data.get('report') or ''
    a = Audit(device_id=device_id, severity=severity, summary=summary, details=details)
    db.session.add(a)
    db.session.commit()
    return jsonify({'status':'ok', 'id': a.id})


@app.route('/devices/<device_id>/audits', methods=['GET'])
@login_required
def view_audits(device_id):
    d = Device.query.get(device_id)
    if not d:
        return jsonify({'status':'error','message':'device not found'}), 404
    rows = Audit.query.filter_by(device_id=device_id).order_by(Audit.timestamp.desc()).all()
    return render_template('device_audits.html', device=d, audits=rows, logged_in=is_logged_in())


@app.route('/devices/<device_id>/install-client', methods=['POST'])
def install_client_on_device(device_id):
    """Trigger server to push the audit client to the device and install as a systemd service.

    JSON body (optional): {"server_url": "http://portal:5000"}
    """
    if not is_logged_in():
        return jsonify({'status': 'error', 'message': 'unauthorized'}), 403
    d = Device.query.get(device_id)
    if not d:
        return jsonify({'status':'error','message':'device not found'}), 404
    data = request.json or {}
    server_url = data.get('server_url') or request.host_url.rstrip('/')
    # ensure device has a token
    token = d.token
    if not token:
        # generate and persist
        tok = __import__('secrets').token_urlsafe(24)
        d.token = tok
        db.session.merge(d)
        db.session.commit()
        token = tok

    # read local device client script
    try:
        script_text = open('device_client.py', 'r', encoding='utf-8').read()
    except Exception as e:
        app.logger.exception('failed reading device_client.py')
        return jsonify({'status':'error','message':'server missing device_client.py'}), 500

    device_info = {'id': d.id, 'host': d.host, 'port': d.port, 'username': d.username, 'password': d.password}

    try:
        out = ssh_mgr.install_client(device_info, script_text, server_url=server_url, token=token)
        return jsonify({'status':'ok','output': out})
    except Exception as e:
        app.logger.exception('install_client error for %s', device_id)
        return jsonify({'status':'error','message': str(e)}), 500


@app.route('/devices/<device_id>/token/regenerate', methods=['POST'])
def regenerate_token(device_id):
    if not is_logged_in():
        return jsonify({'status': 'error', 'message': 'unauthorized'}), 403
    d = Device.query.get(device_id)
    if not d:
        return jsonify({'status':'error','message':'device not found'}), 404
    tok = __import__('secrets').token_urlsafe(32)
    d.token = tok
    db.session.merge(d)
    db.session.commit()
    return jsonify({'status':'ok', 'token': tok})


@app.route('/devices/install-client', methods=['POST'])
def install_client_bulk():
    """Install the client on multiple selected devices.
    Expects JSON: {"ids": ["dev1", "dev2"], "server_url": "http://..."}
    """
    if not is_logged_in():
        return jsonify({'status': 'error', 'message': 'unauthorized'}), 403
    payload = request.json or {}
    ids = payload.get('ids') or []
    server_url = payload.get('server_url') or request.host_url.rstrip('/')
    if not ids:
        return jsonify({'status':'error','message':'no ids provided'}), 400

    # read the client script once
    try:
        script_text = open('device_client.py', 'r', encoding='utf-8').read()
    except Exception:
        app.logger.exception('failed reading device_client.py for bulk install')
        return jsonify({'status':'error','message':'server missing device_client.py'}), 500

    results = {}
    for did in ids:
        d = Device.query.get(did)
        if not d:
            results[did] = {'status':'error','message':'device not found'}
            continue
        token = d.token
        if not token:
            tok = __import__('secrets').token_urlsafe(24)
            d.token = tok
            db.session.merge(d)
            db.session.commit()
            token = tok
        device_info = {'id': d.id, 'host': d.host, 'port': d.port, 'username': d.username, 'password': d.password}
        try:
            out = ssh_mgr.install_client(device_info, script_text, server_url=server_url, token=token)
            results[did] = {'status':'ok','output': out}
        except Exception as e:
            app.logger.exception('bulk install failed for %s', did)
            results[did] = {'status':'error','message': str(e)}

    return jsonify({'results': results})


@app.route('/api/devices/<device_id>/audits', methods=['GET'])
@login_required
def api_audits(device_id):
    rows = Audit.query.filter_by(device_id=device_id).order_by(Audit.timestamp.desc()).limit(200).all()
    out = [{'id': r.id, 'timestamp': r.timestamp.isoformat(), 'severity': r.severity, 'summary': r.summary, 'details': r.details} for r in rows]
    return jsonify({'audits': out})


if __name__ == '__main__':
    # On some Windows environments the debug reloader can cause socket errors on restart.
    # Disable the automatic reloader to avoid OSError: [WinError 10038]
    app.run(debug=True, host='0.0.0.0', use_reloader=False)
