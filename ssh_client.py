import paramiko
import tempfile
import os

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
            return out + '\n' + err
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
            os.write(fd, policy_text.encode('utf-8'))
            os.close(fd)

            sftp = client.open_sftp()
            remote_path = f'/tmp/policy_{device.get("id")}.sh'
            sftp.put(local_path, remote_path)
            sftp.chmod(remote_path, 0o755)
            sftp.close()

            # Execute the policy script
            stdin, stdout, stderr = client.exec_command(f'bash {remote_path}', timeout=120)
            out = stdout.read().decode('utf-8', errors='replace')
            err = stderr.read().decode('utf-8', errors='replace')

            # Cleanup remote and local
            client.exec_command(f'rm -f {remote_path}')
            try:
                os.remove(local_path)
            except Exception:
                pass

            return out + '\n' + err
        finally:
            client.close()
