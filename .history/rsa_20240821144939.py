from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()