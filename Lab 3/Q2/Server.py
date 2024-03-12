import socket
import hmac
import hashlib

SECRET_KEY = "eenameenadeeka"

def generate_mac(secret_key, message):
    secret_key_bytes = bytes(secret_key, 'utf-8')
    message_bytes = bytes(message, 'utf-8')
    hmac_object = hmac.new(secret_key_bytes, message_bytes, hashlib.sha256)
    return hmac_object.hexdigest()

def verify_mac(secret_key, message, received_mac):
    calculated_mac = generate_mac(secret_key, message)
    return hmac.compare_digest(calculated_mac, received_mac)

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    
    print("Server listening...")
    
    while True:
        conn, addr = server_socket.accept()
        print('Connected to', addr)
        
        while True:
            data = conn.recv(1024)
            if not data:
                break
            
            data = data.decode()
            message, received_mac = data.split("|||")
            
            if verify_mac(SECRET_KEY, message, received_mac):
                print("Message received from client:", message)       
                conn.sendall(message.encode())
            else:
                print("Integrity check failed. Message may have been tampered.")
        conn.close()

if __name__ == "__main__":
    main()
