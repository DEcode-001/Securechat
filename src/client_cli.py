"""
SecureChat TLS Client (CLI)
Usage:
  python src/client_cli.py --host 127.0.0.1 --port 8443 --username alice --password secret --pin <SHA256_fingerprint>
"""
import ssl
import sys
import json
import time
import socket
import argparse
import threading
import hashlib

from common import make_message

class CLIClient:
    def __init__(self, host: str, port: int, username: str, password: str, pin_fpr: str):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.counter = 1
        self.pin_fpr = pin_fpr.lower()

    def _fingerprint(self, der_bytes: bytes) -> str:
        return hashlib.sha256(der_bytes).hexdigest()

    def connect(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # we will pin manually
        raw = socket.create_connection((self.host, self.port))
        self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        fpr = self._fingerprint(self.sock.getpeercert(binary_form=True))
        if fpr != self.pin_fpr:
            print('[Client] ERROR: Server fingerprint mismatch! Possible MITM.')
            self.sock.close()
            sys.exit(2)
        # auth
        auth = {'type':'auth','username':self.username,'password':self.password}
        self.sock.sendall((json.dumps(auth)+'\n').encode('utf-8'))
        rf = self.sock.makefile('r', encoding='utf-8', newline='\n')
        line = rf.readline()
        if not line:
            print('[Client] No response from server')
            sys.exit(1)
        resp = json.loads(line)
        if resp.get('type')=='auth' and resp.get('status')=='ok':
            print('[Client] Auth OK. You can start chatting. Type /quit to exit.')
        else:
            print('[Client] Auth FAILED.')
            sys.exit(3)
        # start reader thread
        t = threading.Thread(target=self.reader, args=(rf,), daemon=True)
        t.start()
        self.repl()

    def reader(self, rf):
        for line in rf:
            try:
                msg = json.loads(line)
            except Exception:
                continue
            if msg.get('type')=='chat':
                print(f"[{time.strftime('%H:%M:%S')}] {msg.get('from')}: {msg.get('text')}")
            elif msg.get('type')=='notice':
                print(f"*** {msg.get('message')}")
            elif msg.get('type')=='error':
                print(f"!!! ERROR: {msg.get('message')}")

    def repl(self):
        try:
            while True:
                line = input('> ').strip()
                if line.lower() in ('/quit','/exit'):
                    break
                payload = {'text': line}
                msg = make_message('chat', payload, self.counter)
                self.sock.sendall(msg.encode('utf-8'))
                self.counter += 1
        except KeyboardInterrupt:
            pass
        finally:
            try:
                self.sock.close()
            except Exception:
                pass

if __name__=='__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=8443)
    p.add_argument('--username', required=True)
    p.add_argument('--password', required=True)
    p.add_argument('--pin', required=True, help='SHA256 fingerprint of server certificate (hex)')
    args = p.parse_args()

    CLIClient(args.host, args.port, args.username, args.password, args.pin).connect()