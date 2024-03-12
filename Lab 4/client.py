import socket
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hmac
import os

# Generate RSA key pair for the client
client_key = RSA.generate(2048)

# Generate HMAC key
hmac_key = os.urandom(16)

def generate_hmac(message):
    h = hmac.new(hmac_key, message, hashlib.sha256)
    return h.digest()

def verify_hmac(message, received_hmac):
    expected_hmac = generate_hmac(message)
    return hmac.compare_digest(expected_hmac, received_hmac)

def encrypt_message(message, key):
    cipher_rsa = PKCS1_OAEP.new(key)
    ciphertext = cipher_rsa.encrypt(message)
    return ciphertext

def decrypt_message(ciphertext, key):
    cipher_rsa = PKCS1_OAEP.new(key)
    message = cipher_rsa.decrypt(ciphertext)
    return message

def client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))

    # Send client's public key to the server
    client_socket.sendall(client_key.publickey().export_key())

    # Load server's public key
    server_public_key = RSA.import_key(client_socket.recv(2048))

    # Generate symmetric key for message encryption
    symmetric_key = os.urandom(16)

    # Encrypt symmetric key with server's public key and send to server
    encrypted_symmetric_key = encrypt_message(symmetric_key, server_public_key)
    client_socket.sendall(encrypted_symmetric_key)

    while True:
        message = input("Enter message: ")
        encrypted_message = encrypt_message(message.encode(), symmetric_key)
        hmac_message = generate_hmac(encrypted_message)
        client_socket.sendall(encrypted_message + hmac_message)

        data = client_socket.recv(1024)
        if not data:
            break
        data, received_hmac = data[:-32], data[-32:]
        if verify_hmac(data, received_hmac):
            decrypted_data = decrypt_message(data, symmetric_key)
            print("Received:", decrypted_data.decode())
        else:
            print("HMAC verification failed. Message may have been tampered with.")

    client_socket.close()

if __name__ == "__main__":
    client()
