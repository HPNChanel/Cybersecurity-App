from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
from tkinter import filedialog
import PyPDF2

def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()
    
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    
    encrypt_file = file_path + ".enc"
    with open(encrypt_file, 'wb') as file:
        for x in (cipher.nonce, tag, ciphertext):
            f.write(x)
    
    return encrypt_file

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        nonce, tag, ciphertext = [file.read(x) for x in (16, 16, -1)]
    
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    
    decrypt_file = file_path.replace('.enc', '.dec')
    with open(decrypt_file, 'wb') as file:
        file.write(data)
    
    return 