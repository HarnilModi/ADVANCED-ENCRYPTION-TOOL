import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import filedialog, messagebox

# Function to generate encryption key and IV
def generate_key_iv(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    return key, iv

# Function to encrypt a file
def encrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        salt = os.urandom(16)
        key, iv = generate_key_iv(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Add padding
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_file = file_path + '.enc'

        with open(encrypted_file, 'wb') as ef:
            ef.write(salt + iv + encrypted_data)

        messagebox.showinfo("Success", f"File encrypted successfully: {encrypted_file}")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

# Function to decrypt a file
def decrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as ef:
            data = ef.read()

        salt, iv, encrypted_data = data[:16], data[16:32], data[32:]
        key, _ = generate_key_iv(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        decrypted_file = file_path.replace('.enc', '_decrypted')
        with open(decrypted_file, 'wb') as df:
            df.write(unpadded_data)

        messagebox.showinfo("Success", f"File decrypted successfully: {decrypted_file}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

# GUI for the application
def select_file(action):
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return

    if action == "encrypt":
        encrypt_file(file_path, password)
    elif action == "decrypt":
        decrypt_file(file_path, password)

# Create the main application window
app = tk.Tk()
app.title("Advanced Encryption Tool")
app.geometry("400x200")

# Password input
password_label = tk.Label(app, text="Enter Password:")
password_label.pack(pady=5)
password_entry = tk.Entry(app, show="*", width=30)
password_entry.pack(pady=5)

# Encrypt button
encrypt_button = tk.Button(app, text="Encrypt File", command=lambda: select_file("encrypt"))
encrypt_button.pack(pady=10)

# Decrypt button
decrypt_button = tk.Button(app, text="Decrypt File", command=lambda: select_file("decrypt"))
decrypt_button.pack(pady=10)

# Run the application
app.mainloop()
