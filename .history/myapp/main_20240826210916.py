import tkinter as tk
from tkinter import Text, messagebox, filedialog, Toplevel, ttk, colorchooser
from tkinter.scrolledtext import ScrolledText
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
import random, string
import os
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
        "Ceasar": "Công thức:\nE_n(x) = (x + n) mod 26\nD_n(x) = (x - n) mod 26",
        "Vigenère": "Công thức:\nE_k(x) = (x + k[i]) mod 26\nD_k(x) = (x - k[i]) mod 26",
        "XOR": "Công thức:\nE_k(x) = x XOR k\nD_k(x) = x XOR k",
        "AES": "AES combines permutation and substitution to create a block cipher.\nAES kết hợp hoán vị và thay thế để tạo ra một mã khối.",
        "RSA": "Công thức:\nE_k(x) = x^e mod n\nD_k(x) = x^d mod n",
        "SHA-256": "SHA-256 is a cryptographic hash function.\nIt produces a 256-bit (32-byte) hash value.\nSHA-256 là một hàm băm mật mã.\nNó tạo ra một giá trị băm 256-bit (32-byte)."
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
    text = entry_text.get('1.0', 'end').strip()  # All text from Text widget
    key = entry_key.get('1.0', 'end').strip()
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
        app.config(bg="#2C2C2C")
        frame_input.config(bg="#2C2C2C")
        # frame_algo.config(bg="#2C2C2C")
        # frame_actions.config(bg="#2C2C2C")
        # frame_result.config(bg="#2C2C2C")
        entry_text.config(bg="##454545", fg="#EDEDED", insertbackground='white')
        entry_key.config(bg="##454545", fg="#EDEDED", insertbackground='white')
        entry_password.config(bg="##454545", fg="#EDEDED", insertbackground='white')
        strength_bar.config(bg="##454545", fg="#EDEDED", insertbackground='white')
        # result_display.config(bg="#EDF7F6", fg="#494D5F")
        strength_bar.config(style="dark.Horizontal.TProgressbar")
    else:
        app.config(bg="#EDF7F6")
        frame_input.config(bg="#EDF7F6")
        # frame_algo.config(bg="#EDF7F6")
        # frame_actions.config(bg="#EDF7F6")
        # frame_result.config(bg="#EDF7F6")
        entry_text.config(bg="white", fg="black", insertbackground="black")
        entry_key.config(bg="white", fg="black", insertbackground="black")
        entry_password.config(bg="white", fg="black", insertbackground="black")
        # result_display.config(bg="#494D5F", fg="#EDF7F6")
        strength_bar.config(style="light.Horizontal.TProgressbar")

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

def create_tooltip(widget, text):
    tooltip = tk.Toplevel(widget, bg="white", padx=5, pady=5)
    tooltip.overrideredirect(True)
    tooltip.withdraw()
    label = tk.Label(tooltip, text=text, bg="white", justify="left", relief="solid", borderwidth=1)
    label.pack()
    
    def on_enter(event):
        x = event.x_root + 20
        y = event.y_root + 20
        tooltip.geometry(f"+{x}+{y}")
        tooltip.deiconify()
    
    def on_leave(event):
        tooltip.withdraw()
        
    widget.bind("<Enter>", on_enter)
    widget.bind("<Leave>", on_leave)

# Instruction Wizard
def show_wizard():
    wizard_window = Toplevel(app)
    wizard_window.title("Welcome to Wizard")
    wizard_window.geometry("400x300")
    
    steps = [
        "Step 1: Enter your text in the 'Text' field.",
        "Step 2: Enter the key if required.",
        "Step 3: Choose an algorithm.",
        "Step 4: Click 'Encrypt' or 'Decrypt'."
    ]

    step_text = Text(wizard_window, wrap="word", font=("Helvetica", 12))
    step_text.insert(1.0, "\n".join(steps))
    step_text.config(state="disabled")
    step_text.pack(expand=True, fill="both", padx=10, pady=10)
    
    close_button = ttk.Button(wizard_window, text="Close", command=wizard_window.destroy)
    close_button.pack(pady=10)

# Add menu randomize password
def open_random_password_window():
    random_window = Toplevel(app)
    random_window.title("Randomize Password")
    random_window.geometry("300x200")
    random_window.resizable(False, False)
    
    def generate_password():
        length = int(password_length.get())
        password = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))
        password_entry.delete(0, tk.END)
        password_entry.insert(0, password)
        
    def copy_to_clipboard():
        app.clipboard_clear()
        app.clipboard_append(password_entry.get())
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    
    # Window UI
    ttk.Label(random_window, text="Length:").pack(pady=10)
    password_length = ttk.Spinbox(random_window, from_=8, to=32, width=5)
    password_length.set(12)
    password_length.pack(pady=5)
    
    password_entry = ttk.Entry(random_window, width=25)
    password_entry.pack(pady=5)
    
    ttk.Button(random_window, text="Generate Password", command=generate_password).pack(pady=5)
    ttk.Button(random_window, text="Copy to Clipboard", command=copy_to_clipboard).pack(pady=5)

def toggle_password_visibility():
    if entry_password.cget("show") == '':
        entry_password.config(show='*')
        eye_button.config(image=closed_eye_image)
    else:
        entry_password.config(show='')
        eye_button.config(image=open_eye_image)

def check_password_strength(password):
    # strength_bar.config(value=0)
    if len(password) < 8:
        return "Weak"
    elif not any(char.isdigit() for char in password) or not any(char.isupper() for char in password):
        return "Medium"
    else:
        return "Strong"

# Save count usage to file 
def get_usage_count():
    if not os.path.exists("usage_count.txt"):
        with open("usage_count.txt", 'w') as file:
            file.write('0')
        return 0
    
    with open("usage_count.txt", 'r') as file:
        return int(file.read())

def increment_usage_count():
    count = get_usage_count() + 1
    with open("usage_count.txt", 'w') as file:
        file.write(str(count))
    return count

# Rate the app after 10 times using the app
def on_closing():
    usage_count = increment_usage_count()
    
    if usage_count % 10 == 0:
        rating_window = Toplevel(app)
        rating_window.title("Rate This App")
        rating_window.geometry("600x400")
        
        ttk.Label(rating_window, text="Please rate the app:").pack(pady=10)
        rating_var = tk.IntVar(value=5)
        
        for i in range(1, 6):
            ttk.Radiobutton(rating_window, text=str(i), variable=rating_var, value=i).pack(anchor='w')
        
        ttk.Label(rating_window, text="Feedback:").pack(pady=5)
        feedback_entry = ttk.Entry(rating_window, width=40)
        feedback_entry.pack(pady=5)
        
        def submit_feedback():
            rating = rating_var.get()
            feedback = feedback_entry.get()
            print(f"Rating: {rating}, Feedback: {feedback}")
            rating_window.destroy()
            app.destroy()
        
        submit_button = ttk.Button(rating_window, text="Submit", command=submit_feedback)
        submit_button.pack(pady=10)
        
        cancel_button = ttk.Button(rating_window, text="Cancel", command=rating_window.destroy)
        cancel_button.pack(pady=5)
        
        rating_window.protocol("WM_DELETE_WINDOW", app.destroy)
    else:
        app.destroy()

##################################################################################################################*

app = tk.Tk()
app.title("Encryption Algorithms")

fixed_width = 800
fixed_height = 600

app.geometry(f"{fixed_width}x{fixed_height}")
app.resizable(False, False)

# Sử dụng ttk.Style để tối ưu hóa giao diện các thành phần
style = ttk.Style()
style.configure('TButton', font=('Helvetica', 10), padding=5)
style.configure('TLabel', font=('Helvetica', 10))
style.configure('TEntry', font=('Helvetica', 10))
style.configure('TFrame', background='#EDF7F6')
style.configure('TText', font=('Helvetica', 12))
style.configure('TCombobox', padding=5, font=("Helvetica", 12), background="#f0f0f0", foreground="#333")

# Theme toggle button with a light bulb icon
original_icon = Image.open(r"myapp\assets\light-bulb.png")
resized_icon = original_icon.resize((24, 24), Image.Resampling.LANCZOS)
lightbulb_icon = ImageTk.PhotoImage(resized_icon)
theme_button = ttk.Button(app, image=lightbulb_icon, command=toggle_theme, style="TButton")
theme_button.grid(row=0, column=1, sticky="ne", padx=10, pady=10)

# Frame for input section
frame_input = ttk.Frame(app, padding=(10, 10))
frame_input.grid(row=0, column=0, sticky="nsew")

text_label = ttk.Label(frame_input, text="Text:")
text_label.grid(row=0, column=0, sticky="w")
entry_text = Text(frame_input, height=1, wrap="word")
entry_text.grid(row=0, column=1, padx=3, pady=3, sticky="ew")

key_label = ttk.Label(frame_input, text="Key:")
key_label.grid(row=1, column=0, sticky="w")
entry_key = Text(frame_input, height=1, wrap="word")
entry_key.grid(row=1, column=1, padx=3, pady=3, sticky="ew")

# Frame for algorithm selection
frame_algo = ttk.Frame(app)
frame_algo.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)

var = tk.StringVar(app)
choices = ["Ceasar", "Vigenère", "XOR", "AES", "RSA", "SHA-256"]
select_algorithm_label = ttk.Label(frame_algo, text="Select Algorithm:")
select_algorithm_label.grid(row=0, column=0, sticky="w")
algorithm_combobox = ttk.Combobox(frame_algo, textvariable=var, values=choices, state="readonly", font=("Helvetica", 12))
algorithm_combobox.set("Ceasar")
algorithm_combobox.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

# Frame for action buttons
frame_actions = ttk.Frame(app)
frame_actions.grid(row=2, column=0, sticky="nsew", padx=10, pady=10)

action_button = ttk.Button(frame_actions, text="Encrypt", command=process_text)
action_button.grid(row=0, column=0, padx=5, pady=5)
action_button.bind("<Enter>", lambda e: animate_button(action_button, "#E6E6E6", "#A9A9A9"))
action_button.bind("<Leave>", lambda e: animate_button(action_button, "#A9A9A9", "#E6E6E6"))
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

def choose_bg_color():
    color_code = colorchooser.askcolor(title="Choose your background color")[1]
    if color_code:
        app.config(bg=color_code)
        frame_input.config(bg=color_code)
        frame_algo.config(bg=color_code)
        frame_actions.config(bg=color_code)
        frame_result.config(bg=color_code)

bg_button = ttk.Button(frame_actions, text="Choose Background Color", command=choose_bg_color)
bg_button.grid(row=1, column=4, padx=5, pady=5)

# Thêm menu chọn ngôn ngữ
menu_bar = tk.Menu(app)
app.config(menu=menu_bar)

# Menu Language
lang_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Language", menu=lang_menu)
menu_bar.add_command(label="Help", command=show_help)
lang_menu.add_command(label="English", command=lambda: update_language("en"))
lang_menu.add_command(label="Tiếng Việt", command=lambda: update_language("vi"))

# Tools 
tools_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Tools", menu=tools_menu)
tools_menu.add_command(label="Randomize Password", command=open_random_password_window)
tools_menu.add_command(label="Toggle Theme", command=toggle_theme)
# Make the app responsive
app.grid_rowconfigure(3, weight=1)
app.grid_columnconfigure(0, weight=1)
frame_result.grid_rowconfigure(1, weight=1)
frame_result.grid_columnconfigure(0, weight=1)

# Password label
password_label = ttk.Label(frame_input, text="Password:")
password_label.grid(row=2, column=0, sticky="w")


# Password frame
password_frame = ttk.Frame(frame_input)
password_frame.grid(row=2, column=1, padx=5, pady=5, sticky="ew")

entry_password = ttk.Entry(password_frame, width=34, show="*")
entry_password.grid(row=0, column=0, padx=5, pady=5)
entry_password.bind("<KeyRelease>", lambda e: check_password_strength(entry_password.get()))
# Password strength evaluation
strength_label = ttk.Label(frame_input, text="Strength: ")
strength_label.grid(row=3, column=1, sticky="w")

strength_bar = ttk.Progressbar(frame_input, orient="horizontal", length=200, mode="determinate")
strength_bar.grid(row=3, column=1, padx=5, pady=5, sticky="w")

# Eyes
open_eye_image = ImageTk.PhotoImage(Image.open(r"myapp\assets\open_eye.png").resize((20, 20), Image.Resampling.LANCZOS))
closed_eye_image = ImageTk.PhotoImage(Image.open(r"myapp\assets\closed-eyes.png").resize((20, 20), Image.Resampling.LANCZOS))

eye_button = ttk.Button(password_frame, image=closed_eye_image, command=toggle_password_visibility, style="TButton")
eye_button.grid(row=0, column=1, padx=(5, 0), pady=5)

# Add tooltip to button
create_tooltip(action_button, "Click to encrypt/decrypt the text")
create_tooltip(copy_button, "Copy the result to clipboard")
create_tooltip(save_button, "Save the result to a file")


app.bind('<Configure>', on_resize)
show_wizard()
# Đọc và chỉnh kích thước icon
image = Image.open(r"myapp\assets\logo.jpg")
image = image.resize((16, 16), Image.Resampling.LANCZOS)  # Sử dụng Image.Resampling.LANCZOS cho Pillow 10.0.0+

# Chuyển đổi ảnh thành PhotoImage
icon = ImageTk.PhotoImage(image)

# Đặt icon cho cửa sổ
app.iconphoto(True, icon)

app.protocol("WM_DELETE_WINDOW", on_closing)

app.mainloop()
