"""Device-side security audit client.

Usage:
  python device_client.py --server http://hostname:5000 --device-id <id> --token <token>

This script runs a few lightweight checks and POSTs a JSON audit to
/devices/<device_id>/audits with header X-Device-Token set to the token.
"""
import argparse
import subprocess
import json
import requests
import sys
import time
from pathlib import Path

CHECKS = {
    'uname': ['uname', '-a'],
    'uptime': ['uptime'],
    'whoami': ['whoami'],
    'df': ['df', '-h'],
    'netstat': ['ss', '-tuln']
}


def run_cmd(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=20)
        return out.decode('utf-8', errors='replace')
    except Exception as e:
        return f'error: {e}'


def gather():
    report = {}
    for k, cmd in CHECKS.items():
        report[k] = run_cmd(cmd)
    return report


def read_token(token_file: str = '/etc/rpm-client/token') -> str:
    p = Path(token_file)
    if not p.exists():
        return ''
    try:
        return p.read_text(encoding='utf-8').strip()
    except Exception:
        return ''


def post_audit(server, device_id, token, severity='info', summary='automated security audit'):
    url = server.rstrip('/') + f'/api/devices/{device_id}/audits'
    payload = {
        'severity': severity,
        'summary': summary,
        'details': json.dumps(gather(), indent=2)
    }
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    r = requests.post(url, headers=headers, json=payload, timeout=30)
    return r.status_code, r.text


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--server', help='Portal base URL, e.g. http://portal:5000')
    p.add_argument('--device-id', required=True)
    p.add_argument('--token', help='optional token (if not provided, will read /etc/rpm-client/token)')
    p.add_argument('--token-file', default='/etc/rpm-client/token')
    p.add_argument('--severity', default='info')
    p.add_argument('--summary', default='automated security audit')
    p.add_argument('--daemon', action='store_true', help='run continuously every interval seconds')
    p.add_argument('--interval', type=int, default=3600, help='interval seconds for daemon mode')
    p.add_argument('--once', action='store_true', help='run once and exit')
    args = p.parse_args()

    server = args.server or 'http://127.0.0.1:5000'
    token = args.token or read_token(args.token_file)

    if args.once:
        code, text = post_audit(server, args.device_id, token, severity=args.severity, summary=args.summary)
        print(code)
        print(text)
        sys.exit(0 if code in (200, 201) else 2)

    if args.daemon:
        while True:
            code, text = post_audit(server, args.device_id, token, severity=args.severity, summary=args.summary)
            print(time.strftime('%Y-%m-%d %H:%M:%S'), code)
            time.sleep(args.interval)


if __name__ == '__main__':
    main()
