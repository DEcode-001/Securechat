"""
SecureChat TLS Client (Tkinter GUI)
"""
import ssl
import json
import time
import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from common import make_message

class GUIClient:
    def __init__(self, host, port, pin):
        self.host = host
        self.port = port
        self.pin = pin.lower()
        self.counter = 1
        self.sock = None
        self.rf = None

    def _fingerprint(self, der_bytes: bytes) -> str:
        import hashlib
        return hashlib.sha256(der_bytes).hexdigest()

    def connect(self, username, password):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection((self.host, self.port))
            self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
            fpr = self._fingerprint(self.sock.getpeercert(binary_form=True))
            if fpr != self.pin:
                messagebox.showerror('Security', 'Server fingerprint mismatch!')
                self.sock.close()
                self.sock = None
                return False
            auth = {'type': 'auth', 'username': username, 'password': password}
            # IMPORTANT: keep '\n' so the server reads a complete JSON frame
            self.sock.sendall((json.dumps(auth) + '\n').encode('utf-8'))
            self.rf = self.sock.makefile('r', encoding='utf-8', newline='\n')
            line = self.rf.readline()
            if not line:
                messagebox.showerror('Error', 'No response from server')
                return False
            resp = json.loads(line)
            if resp.get('type') == 'auth' and resp.get('status') == 'ok':
                return True
            messagebox.showerror('Auth', 'Authentication failed')
            return False
        except Exception as e:
            messagebox.showerror('Connect error', str(e))
            return False

    def send_text(self, text):
        msg = make_message('chat', {'text': text}, self.counter)
        self.sock.sendall(msg.encode('utf-8'))
        self.counter += 1

    def reader(self, on_msg):
        for line in self.rf:
            try:
                msg = json.loads(line)
            except Exception:
                continue
            on_msg(msg)

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('SecureChat (GUI)')
        self.geometry('700x450')
        self.client = None
        self._build()

    def _build(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill='both', expand=True)
        # Top: connection
        top = ttk.LabelFrame(frm, text='Connection')
        top.pack(fill='x')
        self.host = tk.StringVar(value='127.0.0.1')
        self.port = tk.IntVar(value=8443)
        self.pin = tk.StringVar(value='')
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        fields = (('Host', self.host), ('Port', self.port),
                  ('PIN', self.pin), ('User', self.username), ('Pass', self.password))
        for i, (lbl, var) in enumerate(fields):
            ttk.Label(top, text=lbl).grid(row=0, column=i*2, sticky='w', padx=5, pady=5)
            e = ttk.Entry(top, textvariable=var, width=18, show='*' if lbl == 'Pass' else None)
            e.grid(row=0, column=i*2+1, sticky='w', padx=5, pady=5)
        self.btn_connect = ttk.Button(top, text='Connect', command=self.on_connect)
        self.btn_connect.grid(row=0, column=10, padx=5)

        # Middle: chat view
        mid = ttk.LabelFrame(frm, text='Chat')
        mid.pack(fill='both', expand=True, pady=10)
        self.text = tk.Text(mid, state='disabled')
        self.text.pack(fill='both', expand=True)

        # Bottom: entry
        bot = ttk.Frame(frm)
        bot.pack(fill='x')
        self.entry = ttk.Entry(bot)
        self.entry.pack(side='left', fill='x', expand=True, padx=5)
        self.entry.bind('<Return>', self.on_send)
        ttk.Button(bot, text='Send', command=self.on_send).pack(side='right', padx=5)

    def on_connect(self):
        self.client = GUIClient(self.host.get(), self.port.get(), self.pin.get())
        if self.client.connect(self.username.get(), self.password.get()):
            self.log('*** Connected. Auth OK.')
            t = threading.Thread(target=self.client.reader, args=(self.on_msg,), daemon=True)
            t.start()

    def on_msg(self, msg):
        if msg.get('type') == 'chat':
            self.log(f"[{time.strftime('%H:%M:%S')}] {msg.get('from')}: {msg.get('text')}")
        elif msg.get('type') == 'notice':
            self.log(f"*** {msg.get('message')}")
        elif msg.get('type') == 'error':
            self.log(f"!!! ERROR: {msg.get('message')}")

    def log(self, s):
        self.text.configure(state='normal')
        self.text.insert('end', s + '\n')
        self.text.configure(state='disabled')
        self.text.see('end')

    def on_send(self, event=None):
        if self.client:
            text = self.entry.get().strip()
            if text:
                self.client.send_text(text)
                self.entry.delete(0, 'end')

if __name__ == '__main__':
    App().mainloop()