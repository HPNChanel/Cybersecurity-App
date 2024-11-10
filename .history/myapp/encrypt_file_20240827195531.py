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
    
    encrypted_file = file_path + ".enc"
    with open(encrypt_file, 'wb') as file:
        for x in (cipher.nonce, tag, ciphertext):
            f.write(x)
    
    return encrypted_file

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        nonce, tag, ciphertext = [file.read(x) for x in (16, 16, -1)]
    
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    
    decrypted_file = file_path.replace('.enc', '.dec')
    with open(decrypt_file, 'wb') as file:
        file.write(data)
    
    return decrypted_file

def convert_to_pdf(encrypted_file):
    pdf_writer = PyPDF2.PdfWriter()
    pdf_writer.add_blank_page(width=210, height=297)  # Create new PDF blank
    
    with open(encrypted_file, 'rb') as file:
        encrypted_content = file.read()
        
    output_pdf = encrypted_file + ".pdf"
    with open(output_pdf, 'wb') as file:
        pdf_writer.write(file)
    
    return output_pdf

def select_and_encrypt_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        key = get_random_bytes(16)  # AES Key
        encrypted_file = encrypt_file(file_path, key)
        pdf_file = convert_to_pdf(encrypted_file)
        print(f"File encrypted and saved as {pdf}")