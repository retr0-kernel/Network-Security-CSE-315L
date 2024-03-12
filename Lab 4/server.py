# import socket
# import hashlib
# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
# import hmac
# import os

# server_key = "ayushkeshriismeandmeisayushkeshri"

# hmac_key = os.urandom(16)

# def generate_hmac(message):
#     h = hmac.new(hmac_key, message, hashlib.sha256)
#     return h.digest()

# def verify_hmac(message, received_hmac):
#     expected_hmac = generate_hmac(message)
#     return hmac.compare_digest(expected_hmac, received_hmac)

# def decrypt_message(ciphertext, key):
#     cipher_rsa = PKCS1_OAEP.new(key)
#     message = cipher_rsa.decrypt(ciphertext)
#     return message

# def server():
#     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server_socket.bind(('localhost', 12345))
#     server_socket.listen(1)
#     print("Server is listening...")

#     conn, addr = server_socket.accept()
#     print('Connected to', addr)

#     client_public_key = RSA.generate(2048)

#     encrypted_symmetric_key = conn.recv(2048)

#     symmetric_key = decrypt_message(encrypted_symmetric_key, server_key)

#     while True:
#         data = conn.recv(1024)
#         if not data:
#             break
#         data, received_hmac = data[:-32], data[-32:]
#         if verify_hmac(data, received_hmac):
#             decrypted_data = decrypt_message(data, symmetric_key)
#             print("Received:", decrypted_data.decode())
#             response = input("Enter response: ")
#             encrypted_response = encrypt_message(response.encode(), symmetric_key)
#             hmac_response = generate_hmac(encrypted_response)
#             conn.sendall(encrypted_response + hmac_response)
#         else:
#             print("HMAC verification failed. Message may have been tampered with.")

#     conn.close()

# if __name__ == "__main__":
#     server()

import socket
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hmac
import os

# Generate RSA key pair for the server
server_key = RSA.generate(2048)

# Generate HMAC key
hmac_key = os.urandom(16)

def generate_hmac(message):
    h = hmac.new(hmac_key, message, hashlib.sha256)
    return h.digest()

def verify_hmac(message, received_hmac):
    expected_hmac = generate_hmac(message)
    return hmac.compare_digest(expected_hmac, received_hmac)

def decrypt_message(ciphertext, key):
    cipher_rsa = PKCS1_OAEP.new(key)
    message = cipher_rsa.decrypt(ciphertext)
    return message

def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    print("Server is listening...")

    conn, addr = server_socket.accept()
    print('Connected to', addr)

    # Load client's public key
    client_public_key = RSA.import_key(conn.recv(2048))

    # Receive encrypted symmetric key from client
    encrypted_symmetric_key = conn.recv(2048)

    # Decrypt symmetric key using server's private key
    symmetric_key = decrypt_message(encrypted_symmetric_key, server_key)

    while True:
        data = conn.recv(1024)
        if not data:
            break
        data, received_hmac = data[:-32], data[-32:]
        if verify_hmac(data, received_hmac):
            decrypted_data = decrypt_message(data, symmetric_key)
            print("Received:", decrypted_data.decode())
            response = input("Enter response: ")
            encrypted_response = encrypt_message(response.encode(), symmetric_key)
            hmac_response = generate_hmac(encrypted_response)
            conn.sendall(encrypted_response + hmac_response)
        else:
            print("HMAC verification failed. Message may have been tampered with.")

    conn.close()

if __name__ == "__main__":
    server()
