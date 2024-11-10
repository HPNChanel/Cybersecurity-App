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
    with open(encrypt_file, 'wb')