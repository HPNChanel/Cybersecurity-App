from Crypto.Cipher import Blowfish, DES, DES3, AES, ChaCha20
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
import base64

# Blowfish Encryption
def blowfish_encrypt(plaintext, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    plen = Blowfish.block_size - len(plaintext) % Blowfish.block_size
    padding = [plen] * plen
    padding = bytes(padding)
    encrypted = cipher.encrypt(plaintext.encode('utf-8') + padding)
    return base64.b64encode(encrypted).decode('utf-8')

# Blowfish Decryption
def blowfish_decrypt(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    plen = decrypted[-1]
    return decrypted[:-plen].decode('utf-8')

# DES Encryption
def des_encrypt(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    plen = DES.block_size - len(plaintext) % DES.block_size
    padding = [plen] * plen
    padding = bytes(padding)
    encrypted = cipher.encrypt(plaintext.encode('utf-8') + padding)
    return base64.b64encode(encrypted).decode('utf-8')

# DES Decryption
def des_decrypt(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    plen = decrypted[-1]
    return decrypted[:-plen].decode('utf-8')

# Triple DES Encryption
def triple_des_encrypt(plaintext, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    plen = DES3.block_size - len(plaintext) % DES3.block_size
    padding = [plen] * plen
    padding = bytes(padding)
    encrypted = cipher.encrypt(plaintext.encode('utf-8') + padding)
    return base64.b64encode(encrypted).decode('utf-8')

# Triple DES Decryption
def triple_des_decrypt(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    cipher = DES3.new(key, DES3.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    plen = decrypted[-1]
    return decrypted[:-plen].decode('utf-8')

# ECC Encryption/Decryption
def ecc_generate_keys():
    key = ECC.generate(curve='P-256')