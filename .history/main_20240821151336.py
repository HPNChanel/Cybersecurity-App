import tkinter as tk
from tkinter import messagebox
from ceasar import ceasar_cipher
from vigenere import vigenere_cipher
from xor import xor_cipher
from aes import aes_decrypt, aes_encrypt
from rsa import rsa_decrypt, rsa_encrypt
from sha256 import sha256_hash

def on_encrypt():
    text = entry_text().get()
    key = entry_key().get()
    algorithm = var.get()
    result = ""
    
    if algorithm == "Ceasar":
        result = ceasar_cipher(text, int(key))
    elif algorithm == "Vigenère":
        result = vigenere_cipher(text, key)
    elif algorithm == "XOR":
        result = xor_cipher(text, int(key))
    elif algorithm == "AES":
        result = aes_encrypt(text, key)
    elif algorithm == "RSA":
        result = rsa_encrypt(text, key)
    elif algorithm == "SHA-256":
        result = sha256_hash(text)
    else:
        result = "Invalid Algorithm"
    
    messagebox.showinfo("Result", f"Encrypted Text: {result}")

def on_decrypt():
    text = entry_text().get()
    key = entry_key().get()
    algorithm = var.get()
    
    result = ""
    
    if algorithm == "Ceasar":
        result = ceasar_cipher(text, -int(key))
    elif algorithm == "AES":
        result = aes_decrypt(text, key)
    elif algorithm == "RSA":
        result = rsa_decrypt(text, key)
    else:
        result = "Decryption not supported for this algorithm"
    
    messagebox.showinfo("Result", f"Decrypted Text: {result}")
    

app = tk.Tk()
app.title("Encryption Algorithms")

tk.Label(app, text="Text").grid(row = 0)
