#2021101237 김윤영
import hashlib #파이썬 해시 알고리즘 라이브러리
import time

def measure_sha_performance(data):
    sha_algorithms = {
        "SHA-224": hashlib.sha224,
        "SHA-256": hashlib.sha256,
        "SHA-384": hashlib.sha384,
        "SHA-512": hashlib.sha512
    }
    performance_results = {}

    for name, algo in sha_algorithms.items():
        start_time = time.time()
        for _ in range(100000):  # 동일 데이터를 여러 번 해시 처리
            algo(data).hexdigest()
        end_time = time.time()
        performance_results[name] = end_time - start_time

    return performance_results
SHA-224, SHA-256, SHA-384, SHA-512

SHAdata_small_filepath = "SHAdata_small.txt"
SHAdata_mid_filepath = "SHAdata_mid.txt"
SHAdata_big_filepath = "SHAdata_big.txt"

with open(SHAdata_small_filepath, 'r', encoding='utf-8') as f:
    SHAdata_small = f.read().encode()  
with open(SHAdata_mid_filepath, 'r', encoding='utf-8') as f:
    SHAdata_mid = f.read().encode()
with open(SHAdata_big_filepath, 'r', encoding='utf-8') as f:
    SHAdata_big = f.read().encode() 
    
# 성능 측정
results = {
    "small" : measure_sha_performance(SHAdata_small),
    "mid" : measure_sha_performance(SHAdata_mid),
    "big" : measure_sha_performance(SHAdata_big)
}

# 결과 출력
for size, result in results.items():
    print(f"\n{size} data 처리 결과:")
    for sha_type, elapsed_time in results[size].items():    
        print(f"{sha_type} 처리 시간: {elapsed_time:.6f} 초")

