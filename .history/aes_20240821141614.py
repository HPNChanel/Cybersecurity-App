from Crypto.Cipher import AES
import base64

def pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def aes_encrypt(plaintext, key):
    key = key.encode('utf-8')
    plaintext = pad(plaintext).encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(plaintext)).decode('utf-8')

def aes_decrypt(ciphertext, key):
    key = key.encode('utf-8')
    ciphertext = base64.b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_ECB)
    return 