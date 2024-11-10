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
    
    result_display.delete(1.0, tk.END)
    result_display.insert(tk.END, result)

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
    
    result_display.delete(1.0, tk.END)
    result_display.insert(tk.END, result)
    

app = tk.Tk()
app.title("Encryption Algorithms")

# Frame for input section
frame_input = tk.Frame(app, padx=10, pady=10)
frame_input.grid(row=0, column=0, sticky="nsew")


tk.Label(app, text="Text").grid(row=0)
entry_text = tk.Entry(app)
entry_text.grid(row=0, column=1)

tk.Label(app, text="Key").grid(row=1)
entry_key = tk.Entry(app)
entry_key.grid(row=1, column=1)

var = tk.StringVar(app)
var.set("Ceasar")
choices = ["Ceasar", "Vigenère", "XOR", "AES", "RSA", "SHA-256"]
option = tk.OptionMenu(app, var, *choices)
option.grid(row=2, column=1)

tk.Button(app, text="Encrypt", command=on_encrypt).grid(row=3, column=1)
tk.Button(app, text="Decrypt", command=on_decrypt).grid(row=4, column=1)

app.mainloop()