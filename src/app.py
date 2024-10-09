import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import simpledialog
from PIL import Image
from Crypto.Cipher import AES
from AESImgEncryption import *

filename_encrypted_ecb = "file_encrypted_ecb.png"  
filename_encrypted_cbc = "file_encrypted_cbc.png"  
filename_decrypted_ecb = "file_decrypted_ecb.png"  
filename_decrypted_cbc = "file_decrypted_cbc.png"
filename_encrypted_cfb = "file_encrypted_cfb.png"  
filename_decrypted_cfb = "file_decrypted_cfb.png"
filename_encrypted_ctr = "file_encrypted_ctr.png" 
filename_decrypted_ctr = "file_decrypted_ctr.png"

# GUI 클래스
class ImageEncryptorApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Image Encryptor")
        
        self.key = None
        self.mode = None
        # 버튼 및 레이아웃 설정
        self.key_button = tk.Button(master, text="Generate Key", command=self.generate_key)
        self.key_button.pack(pady=10)
        
        self.upload_button = tk.Button(master, text="Encrypt Imgae", command=self.upload_image)
        self.upload_button.pack(pady=10)

        self.decrypt_button = tk.Button(master, text="Decrypt Image", command=self.decrypt_image)
        self.decrypt_button.pack(pady=10)

        self.image_path = ""
        
    def upload_image(self):
        self.image_path = filedialog.askopenfilename(
            title="Select an Image", 
            filetypes=[
                ("Image Files", "*.png"),
                ("JPEG Files", "*.jpg"),
                ("JPEG Files", "*.jpeg"),
                ("All Files", "*.*")
            ]
        )
        if self.image_path:
            self.select_mode_and_encrypt()

    def select_mode_and_encrypt(self):
        self.mode = simpledialog.askstring("Select AES Mode", "Enter AES Mode (ECB, CBC, CFB, CTR):")
        if self.mode:
            self.encrypt_image()

    def generate_key(self):
        key_name = simpledialog.askstring("Key Name", "Enter a key name:")
        password = simpledialog.askstring("Password", "Enter a password:")
        
        if key_name and password:
            self.key = key_generator()
            with open(f"{key_name}.bin", 'wb') as key_file:
                key_file.write(self.key)
            with open(f"{key_name}_password.txt", 'w') as pass_file:
                pass_file.write(password)  # Save password as text
            messagebox.showinfo("Info", f"Key saved as {key_name}.bin")

    def encrypt_image(self):
        if not self.image_path or not self.key:
            messagebox.showerror("Error", "Please upload an image and generate a key first!")
            return
        encrypt_image(self.image_path, self.key, self.mode)
        
        messagebox.showinfo("Info", "Image encrypted and saved as 'file_encrypted_ecb.png'")


    def decrypt_image(self):
        key_name = simpledialog.askstring("Key Name", "Enter your key name:")
        password = simpledialog.askstring("Password", "Enter your password:")
        
        try:
            with open(f"{key_name}.bin", 'rb') as key_file:
                loaded_key = key_file.read()
            with open(f"{key_name}_password.txt", 'r') as pass_file:
                saved_password = pass_file.read()  # Load the saved password

            if password != saved_password:
                messagebox.showerror("Error", "Incorrect password!")
                return
        except FileNotFoundError:
            messagebox.showerror("Error", "Key file not found!")
            return

        if self.mode in ['ECB', 'ecb']:
            encrypted_file = 'file_encrypted_ecb.png'
        elif self.mode in ['CBC', 'cbc']:
            encrypted_file = 'file_encrypted_cbc.png'
        elif self.mode in ['CFB', 'cfb']:
            encrypted_file = 'file_encrypted_cfb.png'
        elif self.mode in ['CTR', 'ctr']:
            encrypted_file = 'file_encrypted_ctr.png'
        else:
            messagebox.showerror("Error", "Invalid encryption mode selected.")
            return  

        decrypt_image_from_rgb(encrypted_file, loaded_key, self.mode)
        
        messagebox.showinfo("Info", "Image decrypted and saved as 'decrypted_image.png'")

# 메인 루프 시작
if __name__ == "__main__":
    root = tk.Tk()
    app = ImageEncryptorApp(root)
    root.mainloop()
