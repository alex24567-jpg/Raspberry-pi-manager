import paramiko
import tempfile
import os
import shlex
import hashlib
import re


def _safe_id(s: str) -> str:
    """Return a filesystem- and systemd-safe identifier derived from s.

    Keeps alphanumerics, dash and underscore, replaces others with _, and appends
    an 8-char sha1 suffix to avoid collisions.
    """
    if not s:
        return 'unknown'
    slug = re.sub(r'[^A-Za-z0-9_-]', '_', s)
    h = hashlib.sha1(s.encode('utf-8')).hexdigest()[:8]
    # limit slug length to keep names reasonably short
    if len(slug) > 40:
        slug = slug[:40]
    return f"{slug}-{h}"


class SSHClientManager:
    def __init__(self, username=None, password=None, pkey_path=None):
        self.username = username
        self.password = password
        self.pkey_path = pkey_path

    def _connect(self, host, port=22, username=None, password=None, pkey_path=None, timeout=10):
        username = username or self.username
        password = password or self.password
        pkey_path = pkey_path or self.pkey_path

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if pkey_path:
                key = paramiko.RSAKey.from_private_key_file(pkey_path)
                client.connect(hostname=host, port=port, username=username, pkey=key, timeout=timeout)
            else:
                client.connect(hostname=host, port=port, username=username, password=password, timeout=timeout)
            return client
        except Exception:
            client.close()
            raise

    def run_command(self, device, command, timeout=30):
        host = device.get('host')
        port = device.get('port', 22)
        client = self._connect(host, port=port, username=device.get('username'), password=device.get('password'), pkey_path=device.get('pkey'))
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            out = stdout.read().decode('utf-8', errors='replace')
            err = stderr.read().decode('utf-8', errors='replace')
            # check exit status; raise on non-zero so callers can handle failures
            exit_status = None
            try:
                exit_status = stdout.channel.recv_exit_status()
            except Exception:
                exit_status = None

            combined = out + '\n' + err
            # If we could read an exit code, treat non-zero as failure.
            # If we couldn't read an exit code, but stderr contains data, treat that as failure too
            if (exit_status is not None and exit_status != 0) or (exit_status is None and err.strip()):
                code_part = f"exit code {exit_status}" if exit_status is not None else "(no exit code)"
                raise Exception(f"remote command failed {code_part}\n{combined}")
            return combined
        finally:
            client.close()

    def push_policy(self, device, policy_text):
        """Push a small policy script to the device and run it.
        Returns the command output."""
        host = device.get('host')
        port = device.get('port', 22)
        client = self._connect(host, port=port, username=device.get('username'), password=device.get('password'), pkey_path=device.get('pkey'))
        try:
            # Create a temp file locally
            fd, local_path = tempfile.mkstemp(prefix='policy_', suffix='.sh')
            try:
                os.write(fd, policy_text.encode('utf-8'))
            finally:
                os.close(fd)

            sftp = client.open_sftp()
            # use a safe remote filename derived from device id to avoid spaces/special-char issues
            dev_id = device.get('id') or 'device'
            safe = _safe_id(dev_id)
            remote_path = f'/tmp/policy_{safe}.sh'
            sftp.put(local_path, remote_path)
            sftp.chmod(remote_path, 0o755)
            sftp.close()

            # Execute the policy script (quote path to handle any special chars)
            qpath = shlex.quote(remote_path)
            stdin, stdout, stderr = client.exec_command(f'bash {qpath}', timeout=120)
            out = stdout.read().decode('utf-8', errors='replace')
            err = stderr.read().decode('utf-8', errors='replace')
            # wait and get exit status
            try:
                exit_status = stdout.channel.recv_exit_status()
            except Exception:
                exit_status = None

            # Cleanup remote and local
            client.exec_command(f'rm -f {shlex.quote(remote_path)}')
            try:
                os.remove(local_path)
            except Exception:
                pass

            combined = out + '\n' + err
            # Treat non-zero exit as failure so callers can detect it
            # If exit status isn't available, fall back to treating stderr output as an error indicator
            if (exit_status is not None and exit_status != 0) or (exit_status is None and err.strip()):
                code_part = f"exit code {exit_status}" if exit_status is not None else "(no exit code)"
                raise Exception(f'policy script failed {code_part}\n{combined}')

            return combined
        finally:
            client.close()

    def install_client(self, device, script_text, service_name=None, server_url=None, token=None):
        """Upload a Python client script and install a systemd service on the remote device.

        Notes:
        - This tries to use sudo to move files into system locations and enable the service.
        - The remote user must have sufficient privileges (passwordless sudo or root) for full install.
        """
        host = device.get('host')
        port = device.get('port', 22)
        client = self._connect(host, port=port, username=device.get('username'), password=device.get('password'), pkey_path=device.get('pkey'))
        try:
            sftp = client.open_sftp()
            # write script to a temp path (use safe id)
            dev_id = device.get('id') or 'device'
            safe = _safe_id(dev_id)
            remote_tmp_script = f'/tmp/rpm_client_{safe}.py'
            # token temp file
            remote_tmp_token = f'/tmp/rpm_token_{safe}'
            # write service unit to temp; service name must be systemd-safe (no spaces)
            svc_name = service_name or f'rpm-device-audit-{safe}.service'
            remote_tmp_svc = f'/tmp/{svc_name}'

            # upload script using a local temp file
            fd_script, local_script = tempfile.mkstemp(prefix='__local_rpm_client', suffix='.py')
            try:
                os.write(fd_script, script_text.encode('utf-8'))
            finally:
                os.close(fd_script)

            sftp.put(local_script, remote_tmp_script)

            # upload token file locally and send to remote tmp
            local_token = None
            if token:
                fd_tok, local_token = tempfile.mkstemp(prefix='__local_rpm_token')
                try:
                    os.write(fd_tok, token.encode('utf-8'))
                finally:
                    os.close(fd_tok)
                sftp.put(local_token, remote_tmp_token)

            # prepare service unit content
            args = []
            if server_url:
                args.extend(['--server', server_url])
            if device.get('id'):
                args.extend(['--device-id', device.get('id')])
            if token:
                # prefer token file on disk; service will reference /etc/rpm-client/token
                pass

            # Build ExecStart - include server and device-id if provided so the client
            # won't exit with argparse error (exit code 2). Use shlex.quote for safety.
            cmd_parts = ['/usr/bin/env', 'python3', '/opt/rpm-client/device_client.py', '--daemon', '--token-file', '/etc/rpm-client/token']
            if server_url:
                cmd_parts.extend(['--server', server_url])
            if device.get('id'):
                cmd_parts.extend(['--device-id', device.get('id')])
            exec_cmd = ' '.join(shlex.quote(p) for p in cmd_parts)

            svc_content = f"""[Unit]
Description=RPM Device Audit Client for {device.get('id')}
After=network.target

[Service]
Type=simple
ExecStart={exec_cmd}
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""

            # write service to local temp then upload
            fd_svc, local_svc = tempfile.mkstemp(prefix='__local_rpm_svc', suffix='.service')
            try:
                os.write(fd_svc, svc_content.encode('utf-8'))
            finally:
                os.close(fd_svc)
            sftp.put(local_svc, remote_tmp_svc)
            sftp.close()

            cmds = [
                # create target dir and move script into place
                f'sudo mkdir -p /opt/rpm-client',
                f"sudo mv {shlex.quote(remote_tmp_script)} /opt/rpm-client/device_client.py",
                f'sudo chmod 755 /opt/rpm-client/device_client.py',
                # ensure token dir exists and move token into place with restrictive perms
                'sudo mkdir -p /etc/rpm-client',
                f"sudo mv {shlex.quote(remote_tmp_token)} /etc/rpm-client/token" if token else 'true',
                'sudo chown root:root /etc/rpm-client/token' if token else 'true',
                'sudo chmod 600 /etc/rpm-client/token' if token else 'true',
                # move service unit into systemd dir
                f"sudo mv {shlex.quote(remote_tmp_svc)} /etc/systemd/system/{shlex.quote(svc_name)}",
                'sudo systemctl daemon-reload',
                f'sudo systemctl enable --now {shlex.quote(svc_name)}',
                f'sudo systemctl status {shlex.quote(svc_name)} --no-pager'
            ]

            out_combined = ''
            for c in cmds:
                stdin, stdout, stderr = client.exec_command(c, timeout=60)
                o = stdout.read().decode('utf-8', errors='replace')
                e = stderr.read().decode('utf-8', errors='replace')
                out_combined += f'\n$ {c}\n{ o }\n{ e }\n'

            # cleanup local temps
            try:
                if local_script:
                    os.remove(local_script)
                if local_token:
                    os.remove(local_token)
                if local_svc:
                    os.remove(local_svc)
            except Exception:
                pass

            return out_combined
        finally:
            client.close()
