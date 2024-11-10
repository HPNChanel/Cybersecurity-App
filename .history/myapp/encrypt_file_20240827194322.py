from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
from tkinter import filedialog
import PyPDF2

def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = 