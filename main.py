import tkinter as tk
from tkinter import filedialog
import os
import pyzipper

def encrypt():
    if selected_file:
        print("encrypting...")
        password = input_password()
        if password:
            try:
                encrypt_file(selected_file, password)
            except FileNotFoundError:
                print(f"Error: File '{selected_file}' not found.")
    else:
        print("No file selected.")

def decrypt():
    if selected_file:
        print("decrypting...")
        password = input_password()
        if password:
            try:
                decrypt_file(selected_file, password)
            except FileNotFoundError:
                print(f"Error: File '{selected_file}' not found.")
            except pyzipper.BadZipFile:
                print("Error: Invalid password or corrupted file.")
    else:
        print("No file selected.")

def input_password():
    new_window = tk.Toplevel(mainWindow)
    new_window.title("Enter Password")

    password_var = tk.StringVar()
    password_entry = tk.Entry(new_window, show="*", textvariable=password_var)
    password_entry.grid(row=0, column=1, padx=10, pady=10)

    ok_button = tk.Button(new_window, text="OK", command=lambda: new_window.destroy())
    ok_button.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

    new_window.wait_window()
    return password_var.get()

def encrypt_file(file_path, password):
    encrypted_file_path = file_path + '.enc'
    try:
        with open(file_path, 'rb') as f_in:
            with pyzipper.AESZipFile(encrypted_file_path, 'w', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(password.encode())
                # Get the original file extension
                original_file_name, original_file_ext = os.path.splitext(os.path.basename(file_path))
                # Write the original file name with its extension to the encrypted file
                zf.write(os.path.basename(file_path), f_in.read())
                # Store the original file extension as a comment in the zip file
                zf.comment = original_file_ext.encode()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return

    print(f"File encrypted and saved as: {encrypted_file_path}")

def decrypt_file(file_path, password):
    encrypted_file_path = file_path + '.enc'
    try:
        with pyzipper.AESZipFile(encrypted_file_path, 'r') as zf:
            zf.setpassword(password.encode())
            # Retrieve the original file extension from the comment
            original_file_ext = zf.comment.decode()
            # Extract all files from the encrypted zip file
            for name in zf.namelist():
                # Create the decrypted file path by removing the '.enc' extension
                decrypted_file_path = os.path.join(os.path.dirname(file_path), os.path.splitext(os.path.basename(file_path))[0] + original_file_ext)
                with open(decrypted_file_path, 'wb') as f_out:
                    f_out.write(zf.read(name))
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return
    except pyzipper.BadZipFile:
        print("Error: Invalid password or corrupted file.")
        return

    print(f"File decrypted successfully.")

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

# Frame for buttons
button_frame = tk.Frame(mainWindow, bd=2, relief=tk.GROOVE)
button_frame.pack(side=tk.TOP, fill=tk.X, expand=False, padx=10, pady=10)

# Frame for file information
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
