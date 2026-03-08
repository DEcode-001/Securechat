"""
SecureChat TLS Server (multi-threaded) with authentication, replay protection, and rate limiting.
Usage:
  python src/server.py --host 127.0.0.1 --port 8443
Certs:
  Place certs/server.crt and certs/server.key (self-signed) in the certs/ folder.
"""
import ssl
import sys
import json
import time
import socket
import sqlite3
import argparse
import threading
from pathlib import Path

from common import generate_salt, hash_password, verify_password, parse_message, TokenBucket, ReplayWindow

DB_PATH = Path('artifacts/securechat.db')

def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    salt BLOB NOT NULL,
                    passhash BLOB NOT NULL
                 )""")
    conn.commit()
    conn.close()

def add_user(username: str, password: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    salt = generate_salt()
    pwh = hash_password(password, salt)
    cur.execute('INSERT OR REPLACE INTO users(username, salt, passhash) VALUES(?,?,?)', (username, salt, pwh))
    conn.commit()
    conn.close()

class ClientHandler(threading.Thread):
    def __init__(self, sock: ssl.SSLSocket, addr, server):
        super().__init__(daemon=True)
        self.sock = sock
        self.addr = addr
        self.server = server
        self.username = None
        self.replay = ReplayWindow()
        self.bucket = TokenBucket(capacity=10, fill_rate=5.0)  # 10 burst, 5 msg/sec

    def send(self, msg_obj):
        # IMPORTANT: keep '\n' so clients can read complete JSON frames
        data = (json.dumps(msg_obj) + '\n').encode('utf-8')
        self.sock.sendall(data)

    def run(self):
        try:
            f = self.sock.makefile('r', encoding='utf-8', newline='\n')
            # Authenticate first
            auth_line = f.readline()
            if not auth_line:
                return
            try:
                auth = json.loads(auth_line)
            except Exception:
                self.send({'type': 'error', 'message': 'Invalid auth frame'})
                return
            if auth.get('type') != 'auth':
                self.send({'type': 'error', 'message': 'Auth required first'})
                return

            username = auth.get('username', '')
            password = auth.get('password', '')

            if not self.server.verify_user(username, password):
                self.send({'type': 'auth', 'status': 'fail'})
                return

            self.username = username
            self.send({'type': 'auth', 'status': 'ok'})
            self.server.broadcast({'type': 'notice', 'from': 'server', 'message': f'{self.username} joined'}, self)

            for line in f:
                if not line:
                    break
                try:
                    msg = parse_message(line)
                except Exception:
                    self.send({'type': 'error', 'message': 'Bad message'})
                    continue

                if not self.bucket.consume(1.0):
                    self.send({'type': 'error', 'message': 'Rate limited'})
                    continue

                if not self.replay.check_and_advance(msg.get('counter', 0)):
                    self.send({'type': 'error', 'message': 'Replay/Out-of-order detected'})
                    continue

                if msg.get('type') == 'chat':
                    text = msg.get('payload', {}).get('text', '')
                    out = {'type': 'chat', 'from': self.username, 'text': text, 'ts': time.time()}
                    self.server.broadcast(out, self)
                else:
                    self.send({'type': 'error', 'message': 'Unsupported type'})
        except Exception as e:
            print(f"[Server] Handler error {self.addr}: {e}")
        finally:
            try:
                self.sock.close()
            except Exception:
                pass
            self.server.remove(self)
            if self.username:
                self.server.broadcast({'type': 'notice', 'from': 'server', 'message': f'{self.username} left'}, None)

class SecureChatServer:
    def __init__(self, host: str, port: int, cert_path: Path, key_path: Path):
        self.host = host
        self.port = port
        self.cert_path = cert_path
        self.key_path = key_path
        self.clients = set()
        self._lock = threading.Lock()

    def verify_user(self, username: str, password: str) -> bool:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('SELECT salt, passhash FROM users WHERE username=?', (username,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return False
        salt, pwh = row[0], row[1]
        return verify_password(password, salt, pwh)

    def broadcast(self, msg_obj, src):
        with self._lock:
            for c in list(self.clients):
                try:
                    c.send(msg_obj)
                except Exception:
                    pass

    def remove(self, handler):
        with self._lock:
            self.clients.discard(handler)

    def serve(self):
        print(f"[Server] Listening on {self.host}:{self.port}")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(self.cert_path), keyfile=str(self.key_path))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)
        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                client, addr = ssock.accept()
                handler = ClientHandler(client, addr, self)
                with self._lock:
                    self.clients.add(handler)
                handler.start()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8443)
    parser.add_argument('--add-user', nargs=2, metavar=('USERNAME', 'PASSWORD'))
    args = parser.parse_args()

    init_db()
    if args.add_user:
        add_user(args.add_user[0], args.add_user[1])
        print('[Server] User added')
        sys.exit(0)

    cert = Path('certs/server.crt')
    key = Path('certs/server.key')
    if not cert.exists() or not key.exists():
        print('[Server] ERROR: Missing certs/server.crt or certs/server.key')
        print('        Generate a self-signed cert using scripts/generate_cert.ps1 or OpenSSL.')
        sys.exit(1)

    server = SecureChatServer(args.host, args.port, cert, key)
    server.serve()