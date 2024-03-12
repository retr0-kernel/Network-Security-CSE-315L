import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

def create_key_pair():
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    return private_key, public_key

def load_public_key_from_pem(pem):
    return RSA.import_key(pem)

def serialize_public_key(public_key):
    return public_key.export_key().decode()

def encrypt_message(public_key, message):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message.encode()).hex()

def decrypt_message(private_key, encrypted_message):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(bytes.fromhex(encrypted_message)).decode()

def sign_message(private_key, message):
    h = SHA256.new(message.encode())
    signer = PKCS1_v1_5.new(private_key)
    return signer.sign(h).hex()

def verify_signature(public_key, message, signature):
    h = SHA256.new(message.encode())
    verifier = PKCS1_v1_5.new(public_key)
    return verifier.verify(h, bytes.fromhex(signature))

def send_data(data, connection):
    connection.send(data.encode())

def receive_data(connection):
    return connection.recv(1024).decode()

def exchange_messages(connection, private_key, other_public_key):
    while True:
        outgoing_message = input("You: ")
        outgoing_message = encrypt_message(other_public_key, outgoing_message)
        print("Sent (Encrypted):", outgoing_message, "\n")
        signature = sign_message(private_key, outgoing_message)
        print("Sent (Signature):", signature, "\n")
        send_data(outgoing_message, connection)
        send_data(signature, connection)
        
        message = receive_data(connection)
        print("Received (Encrypted):", message, "\n")
        signature = receive_data(connection)
        print("Received (Signature):", signature, "\n")
        
        if verify_signature(other_public_key, message, signature):
            message = decrypt_message(private_key, message)
            print("Decrypted:", message, "\n")
            print("Signature Verification: Successful", "\n")
        else:
            print("Signature Verification: Failed", "\n")
            continue

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

server_public_key_pem = receive_data(client_socket)
server_public_key = load_public_key_from_pem(server_public_key_pem)

client_private_key, client_public_key = create_key_pair()

send_data(serialize_public_key(client_public_key), client_socket)

exchange_messages(client_socket, client_private_key, server_public_key)
