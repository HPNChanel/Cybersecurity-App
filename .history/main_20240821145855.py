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
    