import socket
from py_ecc.bls import G2ProofOfPossession as bls

def verify_signature(public_key, message, signature):
    return bls.Verify(public_key, message, signature)

def handle_client_connection(client_socket):
    public_key = client_socket.recv(1024).decode()

    while True:
        message = client_socket.recv(1024).decode()
        if not message:
            break
        signature = client_socket.recv(1024).decode()

        if verify_signature(public_key, message, signature):
            print("Signature is valid.")
        else:
            print("Invalid signature.")

    client_socket.close()

def main():
    host = '127.0.0.1'
    port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)

    print(f"Server listening on {host}:{port}")

    while True:
        client_socket, _ = server_socket.accept()
        print("Accepted connection from", client_socket.getpeername())
        handle_client_connection(client_socket)

if __name__ == "__main__":
    main()
