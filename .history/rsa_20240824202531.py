from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def rsa_encrypt(plaintext, public_key_pem):
    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(plaintext.encode())
    return encrypted_message.hex()

def rsa_decrypt(ciphertext, private_key_pem):
    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(bytes.fromhex(ciphertext))
    return decrypted_message.decode()
