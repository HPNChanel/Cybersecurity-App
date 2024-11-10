import tkinter as tk
from tkinter import Text, messagebox, filedialog, Toplevel
from tkinter import ttk
from PIL import Image, ImageTk
import webbrowser
from ceasar import ceasar_cipher
from vigenere import vigenere_cipher
from xor import xor_cipher
from aes import aes_decrypt, aes_encrypt
from rsa import rsa_decrypt, rsa_encrypt
from sha256 import sha256_hash
from languages import set_language, get_text
import tkinter.font as tkFont

# Biến toàn cục để theo dõi trạng thái mã hóa/giải mã
is_encrypt_mode = True
# Biến cờ để kiểm soát việc resize
resize_flag = False

def on_resize(event):
    global resize_flag
    
    if not resize_flag:
        resize_flag = True
        
        # Lấy kích thước mới của cửa sổ
        new_width = event.width
        new_height = event.height

        # Tính toán kích thước mới của các phần tử (ví dụ: thay đổi font size)
        new_font_size = max(8, int(new_height / 20))  # Đảm bảo font không quá nhỏ

        # Điều chỉnh font size cho các widget
        adjust_font_size(entry_text, new_font_size)
        adjust_font_size(entry_key, new_font_size)

        # Thiết lập lại cờ sau khi thay đổi
        app.after(200, lambda: reset_resize_flag())

def reset_resize_flag():
    global resize_flag
    resize_flag = False

def adjust_font_size(widget, new_size):
    font = tkFont.Font(font=widget['font'])
    if font.cget("size") != new_size:  # Chỉ cập nhật nếu kích thước khác
        font.configure(size=new_size)
        widget.config(font=font)
    
def show_formula(algorithm):
    formula_window = Toplevel(app)
    formula_window.title(f"Formula: {algorithm}")

    # Đặt kích thước và căn giữa cửa sổ
    formula_window.geometry("400x300")
    formula_window.resizable(False, False)

    formula_text = get_formula(algorithm)

    # Hiển thị công thức trong một Text widget với định dạng dễ đọc
    formula_label = Text(formula_window, wrap="word", font=("Helvetica", 12), bg="#F0F0F0", relief="flat", borderwidth=0)
    formula_label.insert(1.0, formula_text)
    formula_label.config(state="disabled")  # Chỉ cho phép đọc
    formula_label.pack(expand=True, fill="both", padx=10, pady=10)

def get_formula(algorithm):
    formulas = {
        "Ceasar": "E_n(x) = (x + n) mod 26\nD_n(x) = (x - n) mod 26",
        "Vigenère": "E_k(x) = (x + k[i]) mod 26\nD_k(x) = (x - k[i]) mod 26",
        "XOR": "E_k(x) = x XOR k\nD_k(x) = x XOR k",
        "AES": "AES combines permutation and substitution to create a block cipher.",
        "RSA": "E_k(x) = x^e mod n\nD_k(x) = x^d mod n",
        "SHA-256": "SHA-256 is a cryptographic hash function.\nIt produces a 256-bit (32-byte) hash value."
    }
    return formulas.get(algorithm, "No formula available.")

def validate_key_for_ceasar(key):
    try:
        int(key)
        return True
    except ValueError:
        return False

def animate_button(button, bg_start, bg_end, duration=500):
    steps = 10
    delay = duration // steps
    for i in range(steps):
        bg_colors = "#%02x%02x%02x" % (
            int(bg_start[1:3], 16) + (int(bg_end[1:3], 16) - int(bg_start[1:3], 16)) * i // steps,
            int(bg_start[3:5], 16) + (int(bg_end[3:5], 16) - int(bg_start[3:5], 16)) * i // steps,
            int(bg_start[5:7], 16) + (int(bg_end[5:7], 16) - int(bg_start[5:7], 16)) * i // steps
        )
        button.after(delay * i, lambda color=bg_colors: button.config(style=f"{color}.TButton"))

def process_text():
    text = entry_text.get()
    key = entry_key.get()
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
    
    show_formula(algorithm)  # Hiển thị công thức của thuật toán đã chọn

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
        entry_text.config(bg="#EDF7F6", fg="#494D5F")
        entry_key.config(bg="#EDF7F6", fg="#494D5F")
        result_display.config(bg="#EDF7F6", fg="#494D5F")
    else:
        app.config(bg="#EDF7F6")
        frame_input.config(bg="#EDF7F6")
        frame_algo.config(bg="#EDF7F6")
        frame_actions.config(bg="#EDF7F6")
        frame_result.config(bg="#EDF7F6")
        entry_text.config(bg="#494D5F", fg="#EDF7F6")
        entry_key.config(bg="#494D5F", fg="#EDF7F6")
        result_display.config(bg="#494D5F", fg="#EDF7F6")

def open_facebook():
    webbrowser.open("https://www.facebook.com/profile.php?id=100029692398243")

def update_language(language):
    set_language(language)
    action_button.config(text=get_text("encrypt") if is_encrypt_mode else get_text("decrypt"))
    toggle_mode_button.config(text=get_text("toggle_mode"))
    copy_button.config(text=get_text("copy"))
    save_button.config(text=get_text("save"))
    follow_button.config(text=get_text("facebook"))
    text_label.config(text=get_text("text_label"))
    key_label.config(text=get_text("key_label"))
    select_algorithm_label.config(text=get_text("select_algorithm"))
    result_label.config(text=get_text("result"))

def show_help():
    help_window = Toplevel(app)
    help_window.title("Help")
    help_window.geometry("500x400")
    
    help_text = Text(help_window, wrap="word", font=("Helvetica", 12))
    help_text.insert(1.0, """
    Welcome to the Encryption Algorithms App!

    This app allows you to encrypt and decrypt text using various algorithms like Caesar, Vigenère, XOR, AES, RSA, and SHA-256.

    Here's how to use the app:
    1. Enter the text you want to encrypt or decrypt.
    2. Enter the key if the selected algorithm requires one.
    3. Choose the algorithm from the dropdown.
    4. Click 'Encrypt' or 'Decrypt' based on your need.
    5. Use the 'Copy' button to copy the result or 'Save' to save it to a file.

    Tips:
    - Make sure the key is appropriate for the selected algorithm.
    - You can switch between light and dark mode using the light bulb icon.

    For more information, refer to the documentation provided with this application.
    *********************************************************************************************************
    Chào mừng bạn đến với Encrypt - Decrypt!

    Ứng dụng này cho phép bạn mã hóa và giải mã văn bản bằng cách sử dụng các thuật toán khác nhau như Caesar, Vigenère, XOR, AES, RSA, và SHA-256.

    Cách sử dụng ứng dụng:
    1. Nhập văn bản bạn muốn mã hóa hoặc giải mã.
    2. Nhập khóa nếu thuật toán được chọn yêu cầu một khóa.
    3. Chọn thuật toán từ danh sách thả xuống.
    4. Nhấp vào 'Mã hóa' hoặc 'Giải mã' tùy theo nhu cầu của bạn.
    5. Sử dụng nút 'Sao chép' để sao chép kết quả hoặc 'Lưu' để lưu vào tệp.
    Mẹo:
    - Đảm bảo khóa phù hợp với thuật toán được chọn.
    - Bạn có thể chuyển đổi giữa chế độ sáng và tối bằng cách sử dụng biểu tượng bóng đèn.
    
    Để biết thêm thông tin, hãy tham khảo tài liệu đi kèm với ứng dụng này.
    """)
    
    help_text.config(state="disabled")
    help_text.pack(expand=True, fill="both", padx=10, pady=10)

app = tk.Tk()
app.title("Encryption Algorithms")

app.geometry("800x600")

app.minsize(800, 600)

# Sử dụng ttk.Style để tối ưu hóa giao diện các thành phần
style = ttk.Style()
style.configure('TButton', font=('Helvetica', 10), padding=5)
style.configure('TLabel', font=('Helvetica', 10))
style.configure('TEntry', font=('Helvetica', 10))
style.configure('TFrame', background='#EDF7F6')
style.configure('TText', font=('Helvetica', 12))

# Theme toggle button with a light bulb icon
original_icon = Image.open(r"D:\FOR_WORK\PERSONAL_PROJECT\Python_Project_For_Career\Cybersecurity_App\light-bulb.png")
resized_icon = original_icon.resize((24, 24), Image.Resampling.LANCZOS)
lightbulb_icon = ImageTk.PhotoImage(resized_icon)
theme_button = ttk.Button(app, image=lightbulb_icon, command=toggle_theme, style="TButton")
theme_button.grid(row=0, column=1, sticky="ne", padx=10, pady=10)

# Frame for input section
frame_input = ttk.Frame(app)
frame_input.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

text_label = ttk.Label(frame_input, text="Text")
text_label.grid(row=0, column=0, sticky="w")
entry_text = ttk.Entry(frame_input, width=50)
entry_text.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

key_label = ttk.Label(frame_input, text="Key")
key_label.grid(row=1, column=0, sticky="w")
entry_key = ttk.Entry(frame_input, width=50)
entry_key.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

# Frame for algorithm selection
frame_algo = ttk.Frame(app)
frame_algo.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)

var = tk.StringVar(app)
var.set("Ceasar")
choices = ["Ceasar", "Vigenère", "XOR", "AES", "RSA", "SHA-256"]
select_algorithm_label = ttk.Label(frame_algo, text="Select Algorithm:")
select_algorithm_label.grid(row=0, column=0, sticky="w")
option = ttk.OptionMenu(frame_algo, var, *choices)
option.grid(row=0, column=1, padx=5, pady=5)

# Frame for action buttons
frame_actions = ttk.Frame(app)
frame_actions.grid(row=2, column=0, sticky="nsew", padx=10, pady=10)

action_button = ttk.Button(frame_actions, text="Encrypt", command=process_text)
action_button.grid(row=0, column=0, padx=5, pady=5)
toggle_mode_button = ttk.Button(frame_actions, text="Toggle Mode", command=toggle_mode)
toggle_mode_button.grid(row=0, column=1, padx=5, pady=5)
copy_button = ttk.Button(frame_actions, text="Copy to Clipboard", command=copy_to_clipboard)
copy_button.grid(row=0, column=2, padx=5, pady=5)
save_button = ttk.Button(frame_actions, text="Save to File", command=save_to_file)
save_button.grid(row=0, column=3, padx=5, pady=5)
follow_button = ttk.Button(frame_actions, text="Follow me", command=open_facebook)
follow_button.grid(row=0, column=4, padx=5, pady=5)

# Frame for displaying result
frame_result = ttk.Frame(app)
frame_result.grid(row=3, column=0, sticky="nsew", padx=10, pady=10)

result_label = ttk.Label(frame_result, text="Result:")
result_label.grid(row=0, column=0, sticky="w")

# Adding Text widget with Scrollbar
result_display = Text(frame_result, height=10, width=50, wrap=tk.WORD, font=("Helvetica", 12))
result_display.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

scrollbar = ttk.Scrollbar(frame_result, command=result_display.yview)
scrollbar.grid(row=1, column=1, sticky="nsew")
result_display['yscrollcommand'] = scrollbar.set

# # Thêm Scale widget để thay đổi kích thước font chữ
# font_scale = ttk.Scale(app, from_=8, to=32, orient=tk.HORIZONTAL, command=lambda size: result_display.config(font=("Helvetica", int(size))))
# font_scale.set(12)
# font_scale.grid(row=4, column=0, padx=10, pady=10, sticky="ew")

# Thêm menu chọn ngôn ngữ
menu_bar = tk.Menu(app)
app.config(menu=menu_bar)

# Menu Language
lang_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Language", menu=lang_menu)
menu_bar.add_command(label="Help", command=show_help)
lang_menu.add_command(label="English", command=lambda: update_language("en"))
lang_menu.add_command(label="Tiếng Việt", command=lambda: update_language("vi"))

# Make the app responsive
app.grid_rowconfigure(3, weight=1)
app.grid_columnconfigure(0, weight=1)
frame_result.grid_rowconfigure(1, weight=1)
frame_result.grid_columnconfigure(0, weight=1)

app.bind('<Configure>', on_resize)

# Đọc và chỉnh kích thước icon
image = Image.open(r"D:\FOR_WORK\PERSONAL_PROJECT\Python_Project_For_Career\Cybersecurity_App\logo.jpg")
image = image.resize((16, 16), Image.Resampling.LANCZOS)  # Sử dụng Image.Resampling.LANCZOS cho Pillow 10.0.0+

# Chuyển đổi ảnh thành PhotoImage
icon = ImageTk.PhotoImage(image)

# Đặt icon cho cửa sổ
app.iconphoto(True, icon)

app.mainloop()
