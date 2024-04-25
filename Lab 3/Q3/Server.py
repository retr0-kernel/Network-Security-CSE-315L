import socket
import hmac
import hashlib
def generate_mac(key, message):
key_bytes = bytes(key, 'utf-8') if isinstance(key, str) else key
message_bytes = bytes(message, 'utf-8') if isinstance(message, str) else message
mac = hmac.new(key_bytes, message_bytes, hashlib.sha256)
return mac.hexdigest()
def server():
host = '127.0.0.1'
port = 12345
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
s.bind((host, port))
s.listen()
print(f"Server listening on {host}:{port}")
conn, addr = s.accept()
with conn:
print(f"Connected by {addr}")
secret_key = "key"
received_mac = conn.recv(64).decode('utf-8')
data_received = conn.recv(1024).decode('utf-8')
calculated_mac = generate_mac(secret_key, data_received)
print("rec msg: ",data_received)
print("calc: ",calculated_mac,"\nrec:",received_mac)
if received_mac == calculated_mac:
print("Message Authentication successful.")
else:
print("Message Authentication failed.")
if __name__ == "__main__":
server()