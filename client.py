import socket
from py_ecc.bls import G2ProofOfPossession as bls
from random import randint

def generate_keypair():
    private_key = randint(1, bls.curve_order)
    public_key = bls.SkToPk(private_key)
    return private_key, public_key

def sign_message(private_key, message):
    signature = bls.Sign(private_key, message)
    return signature

def main():
    host = '127.0.0.1'
    port = 12345

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    private_key, public_key = generate_keypair()
    print("Public key:", public_key)

    client_socket.send(public_key.encode())

    while True:
        message = input("Enter message (type 'exit' to quit): ")
        if message == 'exit':
            break

        signature = sign_message(private_key, message)
        print("Signature:", signature)

        client_socket.send(message.encode())
        client_socket.send(signature.encode())

    client_socket.close()

if __name__ == "__main__":
    main()
