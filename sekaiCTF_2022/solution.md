# sekaiCTF 2022 - Cryptography

### 1. Time capsule

In this problem, there are 2 parts to decrypt.
-   The second part can be decrypted easily by getting the seed ( XOR last 18 bytes with b'\x42'*18) and regenerate the key using the seed.
-   The first one is trickier. You may notice that it doesn't use the random keys to encrypt. Instead, it uses the permutation. So we can bruteforce all permutations to decrypt and it's done.

```python
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
```

### 2. Failproof
In order to decrypt the flag, you must understand the happiness function. In short explaination, it returns number of bit 1 in binary presentation . So I come up with an idea to recover it using linear equations. Let's assume a_i is the variable representing i-th bit of message, k_i is the coefficent - the i-th bit of pubkey. We will have some equations like this:
``` a_1*k_1 + a_2*k_2 + ... + a_n*k_n = x (x is known)```
By converting this into matrix, we definitely can recover the mesage.
```python
secret1 = b'\x159\x12\xeb\xa7c$bU\xe2A0\x8ev\x1c\x18'
secret2 = b'\x9d\x02y\xe6\xf4\xe4\xf5\x8a\xa9\xacM\xc40+k.'

enc1 = [[81, 71, 66, 77, 74, 78, 79, 69, 70, 67, 61, 65, 64, 81, 70, 63, 72, 68, 79, 72, 58, 69, 80, 60, 61, 65, 66, 77, 64, 63, 68, 65, 73, 72, 68, 72, 75, 72, 76, 75, 66, 68, 71, 80, 75, 69, 68, 80, 66, 81, 70, 66, 81, 61, 72, 64, 70, 62, 67, 61, 69, 72, 70, 64, 75, 70, 73, 63, 74, 68, 76, 65, 69, 77, 73, 67, 67, 73, 65, 75, 63, 56, 67, 71, 65, 74, 72, 73, 68, 76, 74, 70, 74, 58, 75, 81, 62, 65, 69, 69, 63, 72, 70, 68, 72, 74, 69, 63, 70, 64, 65, 76, 67, 71, 64, 71, 74, 62, 64, 74, 75, 63, 72, 69, 66, 83, 71, 67], [74, 74, 64, 77, 69, 75, 73, 66, 73, 63, 64, 67, 64, 74, 65, 65, 69, 67, 68, 68, 64, 70, 74, 64, 63, 57, 71, 66, 67, 62, 65, 68, 73, 70, 63, 66, 77, 75, 74, 66, 69, 72, 67, 79, 68, 66, 64, 73, 63, 77, 74, 72, 72, 68, 68, 68, 75, 63, 65, 61, 65, 68, 68, 71, 73, 72, 63, 60, 66, 73, 80, 64, 68, 75, 64, 58, 64, 77, 70, 69, 69, 54, 72, 70, 67, 80, 66, 68, 69, 76, 70, 77, 80, 57, 81, 75, 65, 63, 67, 65, 74, 71, 66, 66, 63, 74, 74, 69, 68, 70, 71, 71, 66, 76, 65, 74, 69, 67, 62, 71, 73, 59, 74, 72, 66, 80, 67, 66], [35, 32, 26, 36, 33, 39, 26, 29, 35, 27, 37, 28, 28, 34, 29, 26, 32, 29, 32, 31, 29, 29, 34, 32, 28, 24, 32, 26, 28, 30, 25, 32, 29, 35, 35, 23, 37, 27, 33, 34, 34, 33, 27, 35, 32, 35, 29, 32, 27, 33, 34, 38, 33, 29, 29, 29, 26, 34, 34, 28, 26, 26, 30, 31, 32, 34, 26, 29, 30, 34, 32, 28, 32, 37, 25, 26, 34, 38, 29, 30, 26, 28, 30, 31, 28, 36, 29, 30, 33, 29, 24, 27, 34, 27, 32, 30, 26, 26, 31, 26, 28, 34, 25, 27, 22, 37, 34, 30, 31, 29, 34, 30, 35, 35, 26, 31, 32, 27, 24, 31, 41, 29, 33, 35, 30, 31, 30, 22]]
enc2 = [[76, 64, 75, 67, 66, 74, 75, 78, 71, 74, 69, 64, 72, 73, 64, 73, 60, 71, 58, 76, 56, 78, 79, 77, 65, 72, 60, 65, 65, 74, 71, 69, 68, 78, 67, 66, 68, 68, 73, 74, 65, 64, 68, 81, 69, 66, 74, 77, 65, 63, 77, 77, 64, 69, 83, 65, 67, 71, 69, 74, 66, 69, 67, 75, 82, 65, 75, 74, 71, 64, 71, 66, 80, 67, 68, 68, 79, 64, 78, 76, 66, 76, 79, 76, 82, 68, 67, 70, 56, 61, 71, 76, 67, 62, 76, 75, 72, 67, 76, 65, 71, 73, 85, 64, 73, 74, 76, 68, 68, 68, 61, 83, 63, 71, 79, 74, 75, 73, 61, 64, 70, 64, 74, 71, 64, 79, 74, 64], [72, 73, 79, 64, 60, 72, 75, 85, 63, 66, 65, 68, 64, 68, 59, 71, 59, 68, 61, 74, 61, 73, 78, 65, 68, 71, 56, 59, 59, 78, 65, 66, 65, 76, 68, 69, 62, 72, 68, 73, 68, 65, 64, 66, 62, 63, 77, 70, 58, 56, 67, 76, 66, 73, 85, 65, 71, 70, 69, 77, 66, 68, 68, 72, 73, 75, 69, 67, 67, 68, 71, 65, 78, 61, 67, 63, 68, 69, 75, 75, 71, 71, 76, 68, 76, 71, 65, 65, 59, 60, 70, 76, 66, 57, 69, 62, 77, 66, 80, 68, 67, 68, 81, 70, 65, 63, 72, 60, 65, 62, 66, 80, 59, 74, 74, 65, 69, 73, 61, 64, 68, 64, 77, 66, 67, 72, 73, 59], [33, 33, 27, 29, 27, 30, 32, 36, 29, 29, 32, 26, 32, 30, 26, 30, 25, 32, 28, 34, 25, 34, 30, 30, 26, 30, 25, 25, 27, 34, 27, 30, 28, 31, 33, 27, 20, 26, 28, 33, 27, 30, 31, 35, 26, 28, 30, 25, 27, 28, 34, 32, 34, 30, 35, 28, 29, 33, 29, 40, 30, 34, 23, 27, 36, 27, 32, 30, 29, 28, 30, 32, 32, 28, 28, 29, 33, 27, 37, 32, 28, 29, 28, 24, 36, 32, 30, 31, 25, 29, 27, 30, 32, 26, 27, 29, 30, 25, 35, 34, 27, 32, 44, 30, 33, 34, 36, 27, 24, 25, 36, 26, 28, 37, 36, 27, 32, 36, 26, 33, 35, 26, 24, 26, 27, 32, 32, 29]]

import hashlib
def gen_pubkey(secret: bytes, hasher=hashlib.sha512) -> list:
    def hash(m): return hasher(m).digest()
    state = hash(secret)
    pubkey = []
    for _ in range(len(hash(b'0')) * 4):
        pubkey.append(int.from_bytes(state, 'big'))
        state = hash(state)
    return pubkey
key1 = gen_pubkey(secret1, hasher = hashlib.sha256)
key2 = gen_pubkey(secret2, hasher = hashlib.sha256)
print(len(key1))
a = [[0 for i in range(256)] for j in range(256)]
for i in range(128):
    for j in range(256):
        a[i][j] = Integer((key1[i] >> j) & 1)

    for j in range(256):
        a[i + 128][j] = Integer((key2[i] >> j) & 1)

A = matrix(a)
print(A.rank())
#print(m)
#print(~m)
dec = b'' 
from Crypto.Util.number import long_to_bytes
for num_block in range(3):
    res = enc1[num_block] + enc2[num_block]
    res = vector(res)
    ans = (~A)*res
    num = 0
    for i in range(256):
        if ans[i] == 1:
            num = num | (1<<i)
    dec += long_to_bytes(num)
print(dec)
```

### 3. Secure image encryption
The encryption is based on permutation, so I won't explain too much about it. The hardest part of this challenge is to generate image and send it to the website( because it has captcha so I cannot write a code to automating it, and it took me likes 1 hours to generate the flag).You probaly have to generate about 256 image if you want to recover full flag( the returned image used 8 bit to encode picture, which is 16*16 sized image)

Generating code
```python
from venv import create
from PIL import Image
from pyparsing import col
#generation task, should not be much pain :D

#remember to naming task properly, otherwise u wont know where it  belong to
def create_image(pathfile, x, y):
    img = Image.new('L', (256,256), color = 0)
    d_img = img.load()

    cnt =0 
    for i in range(x, x + 16):
        for j in range(y, y + 16):
            d_img[i,j] = cnt
            cnt += 1
    img.save(pathfile)
    return

for row in range(7, 9):
    for column in range(0,16):
        img_name = 'd:\\generate_image\\img_' + str(row*16 + column) + '.png'
        print('image name:', img_name)
        x = row * 16
        y = column*16
        create_image(img_name, y, x)
        print("Created successfully!!!")

flag_list = [(9, 6), (9,7), (10,5), (10, 6), (11, 4), (11, 5), (12, 3), (12, 4), (6, 8), (6, 9), (5, 9), (5, 10), (4, 10), (4, 11), (3, 11), (3, 12), (2, 12), (2, 13), (1,13), (1,14), (0, 15)]
for row, column in flag_list:
        img_name = 'd:\\generate_image\\img_' + str(row*16 + column) + '.png'
        print('image name:', img_name)
        x = row * 16
        y = column*16
        create_image(img_name, y, x)
        print("Created successfully!!!")


```

Flag recreated code:
```python
from PIL import Image

def calculate_permutation(img_name, enc_name, x, y):
    img = Image.open(img_name)
    enc = Image.open(enc_name)
    d_img = img.load()
    d_enc = enc.load()
    trans = {}
    ans = {}
    for i in range(256):
        for j in range(256):
            if d_enc[i,j] != 0:
                trans[d_enc[i,j]] = (i,j)
    #print(len(trans))
    for i in range(x, x + 16):
        for j in range(y, y + 16):
            if d_img[i,j] != 0:
                ans[(i, j)] = trans[d_img[i,j]]
    
    return ans

original_flag = Image.new('RGB', (256,256), color = (255,255,255))
flag = original_flag.load()

for num in range(112, 143, 2):
    row = num // 16
    column = num%16 
    img_name = 'd:\\generate_image\\img_' + str(num) + '.png'
    ans_name = 'd:\\generate_image\\ans_' + str(num) + '.png'
    x = row * 16
    y = column * 16
    permu1 = calculate_permutation(img_name, ans_name, y, x)

    column += 1
    img_name = 'd:\\generate_image\\img_' + str(num + 1) + '.png'
    ans_name = 'd:\\generate_image\\ans_' + str(num + 1) + '.png'
    x = row * 16
    y = column * 16
    permu2 = calculate_permutation(img_name, ans_name, y, x)
    
    enc_flag = Image.open('d:\\generate_image\\flag_' + str(num) + '.png')
    #print(enc_flag.mode)
    enc = enc_flag.load()
    print(len(permu1))
    print(len(permu2))
    for k, v in permu1.items():
        x1, y1 = k
        x2, y2 = v 
        flag[x1,y1] = enc[x2,y2]
    
    for k, v in permu2.items():
        x1, y1 = k
        x2, y2 = v 
        flag[x1,y1] = enc[x2,y2]
    print('complete:', num)

flag_list = [(9, 6), (9,7), (10,5), (10, 6), (11, 4), (11, 5), (12, 3), (12, 4), (6, 8), (6, 9), (5, 9), (5, 10), (4, 10), (4, 11), (3, 11), (3, 12), (2, 12), (2, 13), (1,13), (1,14), (0, 15)]
for row, column in flag_list:
    num = row * 16 + column
    img_name = 'd:\\generate_image\\img_' + str(num) + '.png'
    ans_name = 'd:\\generate_image\\ans_' + str(num) + '.png'
    x = row * 16
    y = column * 16
    permu1 = calculate_permutation(img_name, ans_name, y, x)
    enc_flag = Image.open('d:\\generate_image\\flag_' + str(num) + '.png')
    #print(enc_flag.mode)
    enc = enc_flag.load()
    print(len(permu1))
    print(len(permu2))
    for k, v in permu1.items():
        x1, y1 = k
        x2, y2 = v 
        flag[x1,y1] = enc[x2,y2]
    print('complete:', num)

for i in range(256):
    for j in range(256):
        if i%16==0 and j%16==0:
            flag[i,j] = (0,0,0)

original_flag.save('d:\\flag_show.png')
```

```Flag: SEKAI{Permutation_is_not_safe_27831169@!!}```

