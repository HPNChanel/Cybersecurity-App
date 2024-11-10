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
    elif algorithm == 