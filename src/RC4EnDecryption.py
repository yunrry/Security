def KSA(key): #KSSA알고리즘
    key_length = len(key)
    S = list(range(256))  # S 배열 초기화
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]  # Swap : 초기 상태 벡터 S 섞기
    return S

def PRGA(S): #PRGA알고리즘으로 평문과 동일한 길이의 keyStream 생성
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # Swap
        K = S[(S[i] + S[j]) % 256]
        yield K

def RC4(key, plaintext):
    key = [ord(c) for c in key]  # key를 아스키 값으로 변환
    S = KSA(key)  # KSA 실행
    keystream = PRGA(S)  # PRGA 실행
    return bytes([c ^ next(keystream) for c in plaintext]) #생성된 KeyStream과 평문을 한 바이트씩 XOR 처리

