import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import simpledialog
from PIL import Image
from Crypto.Cipher import AES
from AESImgEncryption import *
from RC4EnDecryption import *

filename_encrypted_ecb = "file_encrypted_ecb.png"  
filename_encrypted_cbc = "file_encrypted_cbc.png"  
filename_decrypted_ecb = "file_decrypted_ecb.png"  
filename_decrypted_cbc = "file_decrypted_cbc.png"
filename_encrypted_cfb = "file_encrypted_cfb.png"  
filename_decrypted_cfb = "file_decrypted_cfb.png"
filename_encrypted_ctr = "file_encrypted_ctr.png" 
filename_decrypted_ctr = "file_decrypted_ctr.png"


def custom_messagebox(message):
    # 새로운 윈도우 창 생성
        custom_box = tk.Toplevel()
        custom_box.title("contents")

        # 창 크기 설정 (여기서 수동으로 조정 가능)
        custom_box.geometry("300x250")

        # 메시지 텍스트를 포함한 레이블 추가
        label = tk.Label(custom_box, text=str(message), wraplength=250)
        label.pack(pady=20)

        # 확인 버튼 추가
        ok_button = tk.Button(custom_box, text="확인", command=custom_box.destroy)
        ok_button.pack(pady=10)

        # 창이 닫힐 때까지 기다리기
        custom_box.grab_set()
        custom_box.mainloop()
        

# GUI 클래스
class ImageEncryptorApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Encryptor2021101237김윤영")
        
        self.master.geometry("300x400")  # 창 크기를 600x400으로 설정
        
        self.key = None
        self.mode = None
        self.ciphertext = None
        # 버튼 및 레이아웃 설정
        self.key_button = tk.Button(master, text="Generate Key", command=self.generate_key)
        self.key_button.pack(pady=10)
        
        self.upload_button = tk.Button(master, text="Encrypt Imgae", command=self.upload_image)
        self.upload_button.pack(pady=10)

        self.decrypt_button = tk.Button(master, text="Decrypt Image", command=self.decrypt_image)
        self.decrypt_button.pack(pady=10)
        
        self.rc4encrypt_button = tk.Button(master, text="RC4 Encrypt", command=self.RC4encrypt)
        self.rc4encrypt_button.pack(pady=10)
        
        self.rc4decrypt_button = tk.Button(master, text="RC4 Decrypt", command=self.RC4decrypt)
        self.rc4decrypt_button.pack(pady=10)

        self.image_path = ""
        self.stream_path = ""
        self.ciphertext_path = ""
        
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
        
               
    def RC4controller(self, mode):
        key_name = simpledialog.askstring("Key Name", "Enter your key name:")
        password = simpledialog.askstring("Password", "Enter your password:")
        
        try:
            with open(f"{key_name}.bin", 'rb') as key_file:
                loaded_key = key_file.read()
            with open(f"{key_name}_password.txt", 'r') as pass_file:
                key = pass_file.read()  # Load the saved password

            if password != key:
                messagebox.showerror("Error", "Incorrect password!")
                return
        except FileNotFoundError:
            messagebox.showerror("Error", "Key file not found!")
            self.key_button
            return
        
        if mode == 'encrypt':
            with open(self.stream_path, 'r', encoding='utf-8') as f:
                plaintext = f.read().encode()  # 텍스트를 바이트로 변환
            outputtext = RC4(key, plaintext)
            output_file = "RC4encrypted.bin"
            with open(output_file, 'wb') as f:
                f.write(outputtext)
            messagebox.showinfo("Info", "stream encrypted and saved as 'RC4encrypted.bin'")
        
        elif mode == 'decrypt':
            if not isinstance(self.ciphertext, bytes):
                messagebox.showerror("Error", "암호화되지 않은 파일입니다.")
                return
            decrypted = RC4(key, self.ciphertext)
            outputtext = decrypted.decode('utf-8')
            output_file = "RC4decrypted.txt"
            with open(output_file, 'w', encoding='utf-8') as f: 
                f.write(outputtext)
            custom_messagebox(outputtext)
            messagebox.showinfo("Info", "stream decrypted and saved as 'RC4decrypted.txt'")
            

    def RC4encrypt(self):
        self.stream_path = filedialog.askopenfilename(
            title="Select an textfile", 
            filetypes=[
                ("text Files", "*.txt"),
            ]
        )
        if self.stream_path:
            self.RC4controller('encrypt')
        
    def RC4decrypt(self):
        self.ciphertext_path = filedialog.askopenfilename(
            title="Select an textfile", 
            filetypes=[
                ("text Files", "*.bin"),
            ]
        )
        if self.ciphertext_path:
            print(self.ciphertext_path)
            try:
            # 바이너리 파일을 읽어서 바이트 형식으로 저장
                with open(self.ciphertext_path, 'rb') as f:
                    self.ciphertext = f.read()
            except FileNotFoundError:
                messagebox.showerror("Error", "Ciphertext file not found!")
                self.ciphertext = None
            except Exception as e:
                messagebox.showerror("Error", "암호화되지 않은 파일입니다.")
                           
            self.RC4controller('decrypt')   
            
            
# 메인 루프 시작
if __name__ == "__main__":
    root = tk.Tk()
    app = ImageEncryptorApp(root)
    root.mainloop()
