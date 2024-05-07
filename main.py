import tkinter as tk
from tkinter import filedialog, messagebox
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def input_password():
    new_window = tk.Toplevel(mainWindow)
    new_window.title("Enter Password")

    password_label = tk.Label(new_window, text="Input Password:")
    password_label.grid(row=0, column=0, padx=10, pady=10)

    password_var = tk.StringVar()
    password_entry = tk.Entry(new_window, show="*", textvariable=password_var)
    password_entry.grid(row=0, column=1, padx=10, pady=10)

    show_password_var = tk.IntVar()
    show_password_checkbox = tk.Checkbutton(new_window, text="Show Password", variable=show_password_var, command=lambda: show_password(password_entry, show_password_var.get()))
    show_password_checkbox.grid(row=1, column=0, columnspan=2, padx=10, pady=5)

    delete_file_var = tk.IntVar()
    delete_file_checkbox = tk.Checkbutton(new_window, text="Delete File Upon Encryption/Decryption", variable=delete_file_var)
    delete_file_checkbox.grid(row=2, column=0, columnspan=2, padx=10, pady=5)

    ok_button = tk.Button(new_window, text="OK", command=lambda: new_window.destroy())
    ok_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

    # Centering the input password window
    new_window.update_idletasks()
    width = new_window.winfo_width()
    height = new_window.winfo_height()
    x = (new_window.winfo_screenwidth() // 2) - (width // 2)
    y = (new_window.winfo_screenheight() // 2) - (height // 2)
    new_window.geometry('{}x{}+{}+{}'.format(width, height, x, y))

    new_window.wait_window()
    return password_var.get(), delete_file_var.get()

def show_password(password_entry, show):
    if show:
        password_entry.config(show="")
    else:
        password_entry.config(show="*")

def select_file():
    global selected_file
    selected_file = filedialog.askopenfilename()
    update_file_info()

def update_file_info():
    if selected_file:
        file_name = os.path.basename(selected_file)
        file_dir = os.path.dirname(selected_file)
        file_ext = os.path.splitext(selected_file)[1]
        file_info_label.config(text=f"File: {file_name}\nDirectory: {file_dir}\nFormat: {file_ext}")
    else:
        file_info_label.config(text="No file selected.")

def get_key_from_password(password):
    key = hashlib.sha256(password.encode()).digest()
    return key

def encrypt():
    if not selected_file:
        messagebox.showerror("Error", "No file selected for encryption.")
        return

    password, delete_file = input_password()
    key = get_key_from_password(password)

    output_filename = selected_file + ".encrypted"

    try:
        cipher = AES.new(key, AES.MODE_CBC)
        with open(selected_file, 'rb') as f:
            plaintext = f.read()
            padded_plaintext = pad(plaintext, AES.block_size)
            ciphertext = cipher.encrypt(padded_plaintext)
        with open(output_filename, 'wb') as f:
            f.write(cipher.iv)
            f.write(ciphertext)
        messagebox.showinfo("Success", "File encrypted successfully.")

        if delete_file:
            os.remove(selected_file)
            update_file_info()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to encrypt file: {str(e)}")

def decrypt():
    if not selected_file:
        messagebox.showerror("Error", "No file selected for decryption.")
        return

    if not selected_file.endswith(".encrypted"):
        messagebox.showerror("Error", "Please select a .encrypted file for decryption.")
        return

    password, delete_file = input_password()
    key = get_key_from_password(password)

    output_filename = os.path.splitext(selected_file)[0]

    with open(selected_file, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        plaintext = cipher.decrypt(ciphertext)
        unpadded_plaintext = unpad(plaintext, AES.block_size)
        with open(output_filename, 'wb') as f:
            f.write(unpadded_plaintext)
        messagebox.showinfo("Success", "File decrypted successfully.")
    except ValueError:
        messagebox.showerror("Error", "Incorrect password entered.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt file: {str(e)}")

    if delete_file:
        os.remove(selected_file)
        update_file_info()

mainWindow = tk.Tk()
mainWindow.title("AES Application")
mainWindow.resizable(False, False)

window_height = 200
window_width = 400

screen_height = mainWindow.winfo_screenheight()
screen_width = mainWindow.winfo_screenwidth()

center_x = int(screen_width/2 - window_width / 2)
center_y = int(screen_height/2 - window_height / 2)

mainWindow.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')

button_frame = tk.Frame(mainWindow, bd=2, relief=tk.GROOVE)
button_frame.pack(side=tk.TOP, fill=tk.X, expand=False, padx=10, pady=10)

file_info_frame = tk.Frame(mainWindow, bd=2, relief=tk.GROOVE)
file_info_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, padx=10, pady=10)

button_width = 10
button_height = 2

select_file_button = tk.Button(button_frame, text="Select File", command=select_file, width=button_width, height=button_height)
select_file_button.pack(side=tk.LEFT, padx=10, pady=10)

encryptButton = tk.Button(button_frame, text="Encrypt", command=encrypt, width=button_width, height=button_height)
encryptButton.pack(side=tk.LEFT, padx=10, pady=10)

decryptButton = tk.Button(button_frame, text="Decrypt", command=decrypt, width=button_width, height=button_height)
decryptButton.pack(side=tk.LEFT, padx=10, pady=10)

file_info_label = tk.Label(file_info_frame, text="No file selected.")
file_info_label.pack(pady=20)

selected_file = None

mainWindow.mainloop()
