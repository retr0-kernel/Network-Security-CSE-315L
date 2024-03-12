import socket
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

SECRET_KEY = b'eenameenadeeka'

def generate_mac(secret_key, message):
    secret_key_bytes = bytes(secret_key, 'utf-8')
    message_bytes = bytes(message, 'utf-8')
    hmac_object = hmac.new(secret_key_bytes, message_bytes, hashlib.sha256)
    return hmac_object.hexdigest()

def encrypt_message(secret_key, message):
    cipher = AES.new(secret_key, AES.MODE_CBC)
    padded_message = pad(message.encode(), AES.block_size)
    encrypted_message = cipher.iv + cipher.encrypt(padded_message)
    return encrypted_message

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))
    
    while True:
        message = input("Enter message: ")
        encrypted_message = encrypt_message(SECRET_KEY, message)
        mac = generate_mac(SECRET_KEY, encrypted_message)
        message_with_mac = encrypted_message + mac.encode()
        client_socket.sendall(message_with_mac)
        data = client_socket.recv(1024)
        print("Response from server:", data.decode())

    client_socket.close()

if __name__ == "__main__":
    main()
