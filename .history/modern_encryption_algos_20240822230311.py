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
    