enc = open('d:\\flag.enc', 'rb').read()
def xor(a,b):
    return bytes([i ^ j for i, j in zip(a,b)])



import random
def decrypt_stage_two(enc):
    _time = xor(enc[-18:], bytes([0x42] * 18))
    print('seed:',_time)
    random.seed(_time)
    key = [random.randrange(256) for _ in range(len(enc) - 18)]
    return xor(enc[:-18], bytes(key))

def decrypt_stage_one(enc, key):
    res = [b'' for i in range(len(enc))]
    LEN = len(enc)
    ind = 0
    for i in key:
        for j in range(i, len(enc), len(key)):
            res[j] = bytes([enc[ind]])
            ind += 1
    return b''.join(res)



enc1 = decrypt_stage_two(enc)

from itertools import permutations

for i in permutations(range(8)):
    ENC = enc1
    for _time in range(42):
        ENC = decrypt_stage_one(ENC, i)
    
    if b"SEKAI" in ENC:
        print(ENC)
        break