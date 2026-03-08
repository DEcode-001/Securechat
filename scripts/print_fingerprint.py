# Connect to localhost:8443 and print SHA256 fingerprint of server cert
import ssl, socket, hashlib
host='127.0.0.1'
port=8443
ctx = ssl.create_default_context()
ctx.check_hostname=False
ctx.verify_mode=ssl.CERT_NONE
s = ctx.wrap_socket(socket.create_connection((host,port)), server_hostname=host)
fpr = hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest()
print(fpr)
