import socket
import hmac
import hashlib

SECRET_KEY = "eenameenadeeka"

def generate_mac(secret_key, message):
    secret_key_bytes = bytes(secret_key, 'utf-8')
    message_bytes = bytes(message, 'utf-8')
    hmac_object = hmac.new(secret_key_bytes, message_bytes, hashlib.sha256)
    return hmac_object.hexdigest()

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))
    
    while True:
        message = input("Enter message: ")
        mac = generate_mac(SECRET_KEY, message)
        message_with_mac = f"{message}|||{mac}"
        client_socket.sendall(message_with_mac.encode())
        data = client_socket.recv(1024)
        print("Response from server:", data.decode())
    client_socket.close()

if __name__ == "__main__":
    main()
