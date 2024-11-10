import tkinter as tk
from tkinter import Text, messagebox, Scrollbar, filedialog
from tkinter import PhotoImage
from PIL import Image, ImageTk
import tkinter.font as tkFont
import webbrowser
from ceasar import ceasar_cipher
from vigenere import vigenere_cipher
from xor import xor_cipher
from aes import aes_decrypt, aes_encrypt
from rsa import rsa_decrypt, rsa_encrypt
from sha256 import sha256_hash
# from languages import set_language, get_text
# from modern_encryption_algos import (
#     blowfish_encrypt, blowfish_decrypt, des_decrypt, des_encrypt, triple_des_decrypt, triple_des_encrypt,
#     ecc_generate_keys, chacha20_decrypt, chacha20_encrypt
# )

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
    # elif algorithm == "Blowfish":
    #     result = blowfish_encrypt(text, key) if is_encrypt_mode else blowfish_decrypt(text, key)
    # elif algorithm == "DES":
    #     result = des_encrypt(text, key) if is_encrypt_mode else des_decrypt(text, key)
    # elif algorithm == "Triple DES":
    #     result = triple_des_encrypt(text, key) if is_encrypt_mode else triple_des_decrypt(text, key)
    # elif algorithm == "ChaCha20":
    #     result = chacha20_encrypt(text, key) if is_encrypt_mode else chacha20_decrypt(text, key)
    else:
        result = "Invalid Algorithm"
    
    result_display.delete(1.0, tk.END)
    result_display.insert(tk.END, result)


# Change the size of app window
def on_resize(event):
    new_width = event.width
    new_height = event.height
    
    new_font_size = int(new_height / 20)
    
    if 'font' in entry_text.config():
        adjust_font_size(entry_text, new_font_size)
    if 'font' in entry_key.config():
        adjust_font_size(entry_key, new_font_size)

def adjust_font_size(widget, new_size):
    font = tkFont.Font(font=widget['font'])
    font.configure(size=new_size)
    widget.config(font=font)
    
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
    if current_bg == "#EDF7F6":
        app.config(bg="#494D5F")
        frame_input.config(bg="#494D5F")
        frame_algo.config(bg="#494D5F")
        frame_actions.config(bg="#494D5F")
        frame_result.config(bg="#494D5F")
        entry_text.config(bg="EDF7F6", fg="#494D5F")
        entry_key.config(bg="EDF7F6", fg="#494D5F")
        result_display.config(bg="EDF7F6", fg="#494D5F")
    else:
        app.config(bg="#EDF7F6")
        frame_input.config(bg="#EDF7F6")
        frame_algo.config(bg="#EDF7F6")
        frame_actions.config(bg="#EDF7F6")
        frame_result.config(bg="#EDF7F6")
        entry_text.config(bg="#EDF7F6", fg="#494D5F")
        entry_key.config(bg="#EDF7F6", fg="#494D5F")
        result_display.config(bg="#EDF7F6", fg="#494D5F")

def open_facebook():
    webbrowser.open("https://www.facebook.com/profile.php?id=100029692398243")

# def update_language(language):
#     set_language(language)
#     action_button.config(text=get_text("encrypt") if is_encrypt_mode else get_text("decrypt"))
#     toggle_mode_button.config(text=get_text("toggle_mode"))
#     copy_button.config(text=get_text("copy"))
#     save_button.config(text=get_text("save"))
#     follow_button.config(text=get_text("facebook"))
#     text_label.config(text=get_text("text_label"))
#     key_label.config(text=get_text("key_label"))
#     select_algorithm_label.config(text=get_text("select_algorithm"))
#     result_label.config(text=get_text("result"))
    

app = tk.Tk()
app.title("Encryption Algorithms")

# Theme toggle button with a light bulb icon

original_icon = Image.open(r"D:\FOR_WORK\PERSONAL_PROJECT\Python_Project_For_Career\Cybersecurity_App\light-bulb.png")
resized_icon = original_icon.resize((24, 24), Image.Resampling.LANCZOS)
lightbulb_icon = ImageTk.PhotoImage(resized_icon)
theme_button = tk.Button(app, image=lightbulb_icon, command=toggle_theme, bg="white", relief="flat")
theme_button.grid(row=0, column=1, sticky="ne", padx=10, pady=10)


# Frame for input section
frame_input = tk.Frame(app, padx=10, pady=10)
frame_input.grid(row=0, column=0, sticky="nsew")

text_label = tk.Label(frame_input, text="Text").grid(row=0, column=0, sticky="w")
entry_text = tk.Entry(frame_input, width=40)
entry_text.grid(row=0, column=1, padx=5, pady=5)

key_label = tk.Label(app, text="Key").grid(row=1, column=0, sticky="w")
entry_key = tk.Entry(frame_input, width=40)
entry_key.grid(row=1, column=1, padx=5, pady=5)

# Frame for algorithm selection
frame_algo = tk.Frame(app, padx=10, pady=10)
frame_algo.grid(row=1, column=0, sticky="nsew")

var = tk.StringVar(app)
var.set("Ceasar")
choices = ["Ceasar", "Vigenère", "XOR", "AES", "RSA", "SHA-256"]
select_algorithm_label = tk.Label(frame_algo, text="Select Algorithm:").grid(row=0, column=0, sticky="w")
option = tk.OptionMenu(frame_algo, var, *choices)
option.grid(row=0, column=1, padx=5, pady=5)

# Frame for action buttons
frame_actions = tk.Frame(app, padx=10, pady=10)
frame_actions.grid(row=2, column=0, sticky="nsew")

action_button = tk.Button(frame_actions, text="Encrypt", command=process_text)
action_button.grid(row=0, column=0, padx=5, pady=5)
toggle_mode_button = tk.Button(frame_actions, text="Toggle Mode", command=toggle_mode).grid(row=0, column=1, padx=5, pady=5)
copy_button = tk.Button(frame_actions, text="Copy to Clipboard", command=copy_to_clipboard).grid(row=0, column=2, padx=5, pady=5)
save_button = tk.Button(frame_actions, text="Save to File", command=save_to_file).grid(row=0, column=3, padx=5, pady=5)
follow_button = tk.Button(frame_actions, text="Follow me", command=open_facebook).grid(row=0, column=4, padx=5, pady=5)


# Frame for displaying result
frame_result = tk.Frame(app, padx=10, pady=10)
frame_result.grid(row=3, column=0, sticky="nsew")

result_label = tk.Label(frame_result, text="Result:").grid(row=0, column=0, sticky="w")

# Adding Text widget with Scrollbar

result_display = Text(frame_result, height=10, width=50, wrap=tk.WORD, font=("Helvetica", 12))
result_display.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

scrollbar = Scrollbar(frame_result, command=result_display.yview)
scrollbar.grid(row=1, column=1, sticky="nsew")
result_display['yscrollcommand'] = scrollbar.set

# Make the app responsive
app.grid_rowconfigure(3, weight=1)
app.grid_columnconfigure(0, weight=1)
frame_result.grid_rowconfigure(1, weight=1)
frame_result.grid_columnconfigure(0, weight=1)

# Change language
menu_bar = tk.Menu(app)
app.config(menu=menu_bar)

# # Menu language
# lang_menu = tk.Menu(menu_bar, tearoff=0)
# menu_bar.add_cascade(label="Language", menu=lang_menu)
# lang_menu.add_command(label="English", command=lambda: update_language("en"))
# lang_menu.add_command(label="Tiếng Việt", command=lambda: update_language("vi"))

# Icon image app
icon = PhotoImage(file=r"D:\FOR_WORK\PERSONAL_PROJECT\Python_Project_For_Career\Cybersecurity_App\logo.jpg")
app.iconphoto(True, icon)

app.bind("<")
app.mainloop()