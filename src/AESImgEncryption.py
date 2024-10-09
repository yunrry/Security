from PIL import Image
import os
from Crypto.Cipher import AES
from Crypto.Util import Counter

# 파일 경로 설정
# input_filename = '/Users/yunrry/Desktop/4-2/정보보안/AES/sampleImgforAES.png'
# filename_encrypted_ecb = "file_encrypted_ecb.png"  
# filename_encrypted_cbc = "file_encrypted_cbc.png"  
# filename_decrypted_ecb = "file_decrypted_ecb.png"  
# filename_decrypted_cbc = "file_decrypted_cbc.png"
# filename_encrypted_cfb = "file_encrypted_cfb.png"  
# filename_decrypted_cfb = "file_decrypted_cfb.png"
# filename_encrypted_ctr = "file_encrypted_ctr.png" 
# filename_decrypted_ctr = "file_decrypted_ctr.png"
# filename_ctr = "encryption_ctr.bin"  
# filename_key = "encryption_key.bin" 
format = "png"

# AES128을 위한 랜덤 키 생성 함수
def key_generator():
    return os.urandom(16)  # 16바이트 랜덤 키 생성
#--------------------------------------------------------------
# 데이터포맷
def pad(data):
    return data + b"\x00" * (16 - len(data) % 16)

def unpad(data):
    # 데이터의 길이를 구하기
    padding_length = 0
    # 데이터의 끝에서 0x00의 개수를 세어 패딩 길이를 결정.
    for i in range(1, 17):  # 최대 16바이트의 패딩을 고려.
        if data[-i] == 0:  # 0x00이면 패딩으로 간주.
            padding_length += 1
        else:
            break  # 0x00이 아닌 값을 만나면 종료
    # 원래 데이터 길이를 반환
    return data[:-padding_length] if padding_length > 0 else data  # 패딩이 없으면 원본 데이터 반환

# RGB이미지 변환
def trans_format_RGB(data): 
    red, green, blue = tuple(map(lambda e: [data[i] for i in range(0, len(data)) if i % 3 == e], [0, 1, 2]))
    pixels = tuple(zip(red, green, blue))
    return pixels


#--------------------------------------------------------------
# 이미지파일 암호화
def encrypt_image(filename, key, mode):
    im = Image.open(filename)
    value_vector = im.convert("RGB").tobytes()
    imlength = len(value_vector)

    if mode in ['ECB', 'ecb']:
        encrypt_data = aes_ecb_encrypt(key, pad(value_vector))
        target_file = filename_encrypted_ecb
    elif mode == "cbc":
        encrypt_data = aes_cbc_encrypt(key, pad(value_vector))
        target_file = filename_encrypted_cbc
    elif mode == "cfb":
        encrypt_data = aes_cfb_encrypt(key, pad(value_vector))
        target_file = filename_encrypted_cfb
    elif mode == "ctr":
        encrypt_data = aes_ctr_encrypt(key, pad(value_vector))    
        target_file = filename_encrypted_ctr

    encrypted_img = trans_format_RGB(encrypt_data[:imlength])

    im2 = Image.new(im.mode, im.size)
    im2.putdata(encrypted_img)
    im2.save(target_file, format)
    

#--------------------------------------------------------------
# 이미지파일 복호화
def decrypt_image_from_rgb(filename, key, mode):
    with Image.open(filename) as im:
        rgb_data = im.convert("RGB").tobytes()  
    print("RGB Data Length:", len(rgb_data))
    imlength = len(rgb_data)

    if mode == "ecb":
        decrypted_data = aes_ecb_decrypt(key, unpad(rgb_data))
        target_file = filename_decrypted_ecb
    elif mode == "cbc":
        decrypted_data = aes_cbc_decrypt(key, unpad(rgb_data))
        target_file = filename_decrypted_cbc
    elif mode == "cfb":
        decrypted_data = aes_cfb_decrypt(key, unpad(rgb_data))
        target_file = filename_decrypted_cfb
    elif mode == "ctr":
        decrypted_data = aes_ctr_decrypt(key, unpad(rgb_data))    
        target_file = filename_decrypted_ctr  

    decrypted_img = trans_format_RGB(decrypted_data[:imlength])
 
    im2 = Image.new(im.mode, im.size)
    im2.putdata(decrypted_img)
    im2.save(target_file, format)


    
#---------------------------------------
#AES 암호화 함수

def aes_ecb_encrypt(key, data, mode=AES.MODE_ECB):
    aes = AES.new(key, mode)
    new_data = aes.encrypt(data)
    return new_data

def aes_cbc_encrypt(key, data, mode=AES.MODE_CBC):
    IV = os.urandom(16) 
    aes = AES.new(key, mode, IV)
    new_data = aes.encrypt(data)
    return new_data

def aes_cfb_encrypt(key, data, mode=AES.MODE_CFB):
    IV = os.urandom(16) 
    aes = AES.new(key, mode, IV)
    new_data = aes.encrypt(data)
    return new_data

def aes_ctr_encrypt(key, data, mode=AES.MODE_CTR):
   # Generate a unique nonce (8 bytes)
    nonce = os.urandom(8)
    counter_value = 0  # Start counter value

    # Save the nonce and counter value
    save_ctr(nonce, counter_value, filename_ctr)

    # Create a Counter object with the nonce and counter value
    ctr = Counter.new(64, prefix=nonce, initial_value=counter_value)

    aes = AES.new(key, mode, counter=ctr)
    new_data = aes.encrypt(data)
    return new_data


#---------------------------------------
#AES 복호화 함수
def aes_ecb_decrypt(key, data):
    aes = AES.new(key, AES.MODE_ECB)
    decrypted = aes.decrypt(data) 
    return decrypted 

def aes_cbc_decrypt(key, data):
    aes = AES.new(key, mode=AES.MODE_CBC)
    decrypted = aes.decrypt(data)
    return decrypted

def aes_cfb_decrypt(key, data):
    aes = AES.new(key, mode=AES.MODE_CFB)
    decrypted = aes.decrypt(data)
    return decrypted

def aes_ctr_decrypt(key, data):
    # Load the nonce and counter value from the file
    nonce, counter_value = load_counter(filename_ctr)

    # Create a Counter object
    ctr = Counter.new(64, prefix=nonce, initial_value=counter_value)


    aes = AES.new(key, mode=AES.MODE_CTR, counter=ctr)
    decrypted = aes.encrypt(data)
    return decrypted
        
        
        
def save_ctr(nonce, counter_value, filename):
    with open(filename, 'wb') as f:
        f.write(nonce)  # Save the nonce (8 bytes)
        f.write(counter_value.to_bytes(8, byteorder='big'))  # Save the counter value (8 bytes)

def load_counter(filename):
    with open(filename, 'rb') as f:
        nonce = f.read(8)  # Read the nonce
        counter_value = int.from_bytes(f.read(8), byteorder='big')  # Read the counter value
    return nonce, counter_value
                
def load_key(filename):
    with open(filename, 'rb') as f:
        return f.read()  # Read the key from the file
    
# loaded_key = load_key(filename_key)




##TEST-------------------------------------------------------
# encrypt_image(input_filename, loaded_key, 'ecb')
# decrypt_image_from_rgb(filename_encrypted_ctr, loaded_key, 'ecb') 

