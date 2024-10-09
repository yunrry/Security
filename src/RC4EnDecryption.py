def KSA(key):
    key_length = len(key)
    S = list(range(256))  # S 배열 초기화
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]  # Swap
    return S

def PRGA(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # Swap
        K = S[(S[i] + S[j]) % 256]
        yield K

def RC4(key, plaintext):
    print(plaintext)
    key = [ord(c) for c in key]  # key를 아스키 값으로 변환
    S = KSA(key)  # KSA 실행
    keystream = PRGA(S)  # PRGA 실행
    return bytes([c ^ next(keystream) for c in plaintext])

# # 테스트
# key = "mysecretkey"
# plaintext = "Hello, RC4!".encode()  # 평문을 바이트로 인코딩
# ciphertext = RC4(key, plaintext)
# print("암호문:", ciphertext)

# # 복호화 테스트 (RC4의 대칭성 사용)
# decrypted = RC4(key, ciphertext)
# print("복호문:", decrypted.decode())
