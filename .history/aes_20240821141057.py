from Crypto.Cipher import AES
import base64

def pad(s):
    return s + (AES.block_size )