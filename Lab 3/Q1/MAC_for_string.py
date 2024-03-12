import hmac
import hashlib

def generate_mac(secret_key, message):
    secret_key_bytes = bytes(secret_key, 'utf-8')
    message_bytes = bytes(message, 'utf-8')
    hmac_object = hmac.new(secret_key_bytes, message_bytes, hashlib.sha256)
    return hmac_object.hexdigest()

secret_key = "eenameenadeeka"
message = "My name is Krish Srivastava"
mac = generate_mac(secret_key, message)

print(f"Message: {message}")
print(f"MAC: {mac}")