import tkinter as tk
from tkinter import Text, messagebox, Scrollbar, filedialog
from tkinter import PhotoImage
from PIL import Image, ImageTk
from ceasar import ceasar_cipher
from vigenere import vigenere_cipher
from xor import xor_cipher
from aes import aes_decrypt, aes_encrypt
from rsa import rsa_decrypt, rsa_encrypt
from sha256 import sha256_hash

# Global variable to track the current mode
is_encrypt_mode = True

def validate_key_for_ceasar(key):
    try:
        int(key)
        return True
    except ValueError:
        return False

def process_text():
    text = entry_text.get() #!
    key = entry_key.get() #!
    algorithm = var.get()
    result = ""
    
    if algorithm == "Ceasar":
        if not validate_key_for_ceasar(key):
            messagebox.showerror("Invalid Key", "Key for Ceasar cipher must be an integer.")
            return
        result = ceasar_cipher(text, int(key)) if is_encrypt_mode else ceasar_cipher(text, -int(key))
    elif algorithm == "Vigenère":
        result = vigenere_cipher(text, key) if is_encrypt_mode else vigenere_cipher(text, key)
    elif algorithm == "XOR":
        result = xor_cipher(text, int(key))
    elif algorithm == "AES":
        result = aes_encrypt(text, key) if is_encrypt_mode else aes_decrypt(text, key) 
    elif algorithm == "RSA":
        result = rsa_encrypt(text, key) if is_encrypt_mode else rsa_decrypt(text, key)
    elif algorithm == "SHA-256":
        result = sha256_hash(text) if is_encrypt_mode else "SHA-256 is a hash function, not reversible"
    else:
        result = "Invalid Algorithm"
    
    result_display.delete(1.0, tk.END)
    result_display.insert(tk.END, result)


    
def copy_to_clipboard():
    app.clipboard_clear()
    app.clipboard_append(result_display.get(1.0, tk.END).strip())
    messagebox.showinfo("Copy Success", "The result has been copied to clipboard.")

def save_to_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(result_display.get(1.0, tk.END).strip())
        messagebox.showinfo("Save Success", f"File saved to {file_path}")

def toggle_mode():
    global is_encrypt_mode
    is_encrypt_mode = not is_encrypt_mode
    action_button.config(text="Encrypt" if is_encrypt_mode else "Decrypt")

def toggle_theme():
    current_bg = app.cget('bg')
    if current_bg == "white":
        app.config(bg="#49")
        frame_input.config(bg="#a28089")
        frame_algo.config(bg="#a28089")
        frame_actions.config(bg="#a28089")
        frame_result.config(bg="#a28089")
        entry_text.config(bg="gray", fg="white")
        entry_key.config(bg="gray", fg="white")
        result_display.config(bg="gray", fg="white")
    else:
        app.config(bg="white")
        frame_input.config(bg="white")
        frame_algo.config(bg="white")
        frame_actions.config(bg="white")
        frame_result.config(bg="white")
        entry_text.config(bg="white", fg="black")
        entry_key.config(bg="white", fg="black")
        result_display.config(bg="white", fg="black")

app = tk.Tk()
app.title("Encryption Algorithms")

# Theme toggle button with a light bulb icon

original_icon = Image.open("D:\FOR_WORK\PERSONAL_PROJECT\Python_Project_For_Career\Cybersecurity_App\light-bulb.png")
resized_icon = original_icon.resize((24, 24), Image.Resampling.LANCZOS)
lightbulb_icon = ImageTk.PhotoImage(resized_icon)
theme_button = tk.Button(app, image=lightbulb_icon, command=toggle_theme, bg="white", relief="flat")
theme_button.grid(row=0, column=1, sticky="ne", padx=10, pady=10)

# Frame for input section
frame_input = tk.Frame(app, padx=10, pady=10)
frame_input.grid(row=0, column=0, sticky="nsew")

tk.Label(frame_input, text="Text").grid(row=0, column=0, sticky="w")
entry_text = tk.Entry(frame_input, width=40)
entry_text.grid(row=0, column=1, padx=5, pady=5)

tk.Label(app, text="Key").grid(row=1, column=0, sticky="w")
entry_key = tk.Entry(frame_input, width=40)
entry_key.grid(row=1, column=1, padx=5, pady=5)

# Frame for algorithm selection
frame_algo = tk.Frame(app, padx=10, pady=10)
frame_algo.grid(row=1, column=0, sticky="nsew")

var = tk.StringVar(app)
var.set("Ceasar")
choices = ["Ceasar", "Vigenère", "XOR", "AES", "RSA", "SHA-256"]
tk.Label(frame_algo, text="Select Algorithm:").grid(row=0, column=0, sticky="w")
option = tk.OptionMenu(frame_algo, var, *choices)
option.grid(row=0, column=1, padx=5, pady=5)

# Frame for action buttons
frame_actions = tk.Frame(app, padx=10, pady=10)
frame_actions.grid(row=2, column=0, sticky="nsew")

action_button = tk.Button(frame_actions, text="Encrypt", command=process_text)
action_button.grid(row=0, column=0, padx=5, pady=5)
tk.Button(frame_actions, text="Toggle Mode", command=toggle_mode).grid(row=0, column=1, padx=5, pady=5)
tk.Button(frame_actions, text="Copy to Clipboard", command=copy_to_clipboard).grid(row=0, column=2, padx=5, pady=5)
tk.Button(frame_actions, text="Save to File", command=save_to_file).grid(row=0, column=3, padx=5, pady=5)

# Frame for displaying result
frame_result = tk.Frame(app, padx=10, pady=10)
frame_result.grid(row=3, column=0, sticky="nsew")

tk.Label(frame_result, text="Result:").grid(row=0, column=0, sticky="w")

# Adding Text widget with Scrollbar

result_display = Text(frame_result, height=10, width=50)
result_display.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

scrollbar = Scrollbar(frame_result, command=result_display.yview)
scrollbar.grid(row=1, column=1, sticky="nsew")
result_display['yscrollcommand'] = scrollbar.set

# Make the app responsive
app.grid_rowconfigure(3, weight=1)
app.grid_columnconfigure(0, weight=1)
frame_result.grid_rowconfigure(1, weight=1)
frame_result.grid_columnconfigure(0, weight=1)

app.mainloop()