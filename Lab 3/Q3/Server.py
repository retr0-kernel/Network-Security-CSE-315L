import socket
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

SECRET_KEY = b'eenameenadeeka'

def generate_mac(secret_key, message):
    secret_key_bytes = bytes(secret_key, 'utf-8')
    message_bytes = bytes(message, 'utf-8')
    hmac_object = hmac.new(secret_key_bytes, message_bytes, hashlib.sha256)
    return hmac_object.hexdigest()

def verify_mac(secret_key, message, received_mac):
    calculated_mac = generate_mac(secret_key, message)
    return hmac.compare_digest(calculated_mac, received_mac)

def decrypt_message(secret_key, encrypted_message):
    cipher = AES.new(secret_key, AES.MODE_CBC, iv=encrypted_message[:16])
    decrypted_message = unpad(cipher.decrypt(encrypted_message[16:]), AES.block_size)
    return decrypted_message.decode()

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    
    print("Server listening...")
    
    while True:
        conn, addr = server_socket.accept()
        print('Connected to', addr)
        
        while True:
            # Receive data from client
            data = conn.recv(1024)
            if not data:
                break
            
            encrypted_message = data[:-64]
            received_hmac = data[-64:]
            
            if verify_mac(SECRET_KEY, encrypted_message, received_hmac):
                decrypted_message = decrypt_message(SECRET_KEY, encrypted_message)
                print("Message received from client:", decrypted_message)
                
                conn.sendall(encrypted_message)
            else:
                print("Message may have been tampered.")
        
        conn.close()

if __name__ == "__main__":
    main()