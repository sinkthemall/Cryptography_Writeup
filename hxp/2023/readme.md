# HXP CTF Writeup 2023 (Cryptography)
### 1. Yor

```python
#!/usr/bin/env python3
import random

greets = [
        "Herzlich willkommen! Der Schlüssel ist {0}, und die Flagge lautet {1}.",
        "Bienvenue! Le clé est {0}, et le drapeau est {1}.",
        "Hartelĳk welkom! De sleutel is {0}, en de vlag luidt {1}.",
        "ようこそ！鍵は{0}、旗は{1}です。",
        "歡迎！鑰匙是{0}，旗幟是{1}。",
        "Witamy! Niestety nie mówię po polsku...",
    ]

flag = open('flag.txt').read().strip()
assert set(flag.encode()) <= set(range(0x20,0x7f))

key = bytes(random.randrange(256) for _ in range(16))
hello = random.choice(greets).format(key.hex(), flag).encode()

output = bytes(y | key[i%len(key)] for i,y in enumerate(hello))
print(output.hex())
```

This problem is similar to other otp challenge, with somepart of plaintext is repeatedly, except that they use '|' instead of '^'. So how can we solve this challenge?
Actually it can be solved with a little trick. If the i-th bit in plaintext is 0 then i-th bit in ciphertext is the i-th bit of the key, because ``` 0 ^ a = a```.
And because of that, we only collect the bit 0 of the key, and use that to find the flag. We will repeat this process until we find full flag. Unfortunately, this challenge finish 2 month ago when i begin writing this writeup, so there isn't solution file. I will consider this as a practice for you guys.
 
### 2.Whistler

```python
#!/usr/bin/env python3
import struct, hashlib, random, os
from Crypto.Cipher import AES

n = 256
q = 11777
w = 8

################################################################

sample = lambda rng: [bin(rng.getrandbits(w)).count('1') - w//2 for _ in range(n)]

add = lambda f,g: [(x + y) % q for x,y in zip(f,g)]

def mul(f,g):
    r = [0]*n
    for i,x in enumerate(f):
        for j,y in enumerate(g):
            s,k = divmod(i+j, n)
            r[k] += (-1)**s * x*y
            r[k] %= q
    return r

################################################################

def genkey():
    a = [random.randrange(q) for _ in range(n)]
    rng = random.SystemRandom()
    s,e = sample(rng), sample(rng)
    b = add(mul(a,s), e)
    return s, (a,b)

center = lambda v: min(v%q, v%q-q, key=abs)
extract = lambda r,d: [2*t//q for u,t in zip(r,d) if u]

ppoly = lambda g: struct.pack(f'<{n}H', *g).hex()
pbits = lambda g: ''.join(str(int(v)) for v in g)
hbits = lambda g: hashlib.sha256(pbits(g).encode()).digest()
mkaes = lambda bits: AES.new(hbits(bits), AES.MODE_CTR, nonce=b'')

def encaps(pk):
    seed = os.urandom(32)
    rng = random.Random(seed)
    a,b = pk
    s,e = sample(rng), sample(rng)
    c = add(mul(a,s), e)
    d = add(mul(b,s), e)
    r = [int(abs(center(2*v)) > q//7) for v in d]
    bits = extract(r,d)
    return bits, (c,r)

def decaps(sk, ct):
    s = sk
    c,r = ct
    d = mul(c,s)
    return extract(r,d)

################################################################

if __name__ == '__main__':

    while True:
        sk, pk = genkey()
        dh, ct = encaps(pk)
        if decaps(sk, ct) == dh:
            break

    print('pk[0]:', ppoly(pk[0]))
    print('pk[1]:', ppoly(pk[1]))

    print('ct[0]:', ppoly(ct[0]))
    print('ct[1]:', pbits(ct[1]))

    flag = open('flag.txt').read().strip()
    print('flag: ', mkaes([0]+dh).encrypt(flag.encode()).hex())

    for _ in range(2048):
        c = list(struct.unpack(f'<{n}H', bytes.fromhex(input())))
        r = list(map('01'.index, input()))
        if len(r) != n or sum(r) < n//2: exit('!!!')

        bits = decaps(sk, (c,r))

        print(mkaes([1]+bits).encrypt(b'hxp<3you').hex())
```
There are many ways to solve this challenge, and i will introduce to you one of the trickiest way( considering that you guys have read and understanded the file)
Lets consider a state : ```r = 0 1 0 0 1 1 0```. For each index i in r and j = i - 1( i and j are adjacent and ```r[i]=1 and r[j]=1```), we will send to server 2 times, the first will be ```r``` with  ```r[i]=0``` and the second will be ```r[j]=0```, then we will receive 2 ciphertext corresponding to 2 params. If 2 ciphertext are same, then ```bit[i]=bit[j]```
else ```bit[i]=bit[j]^1```, repeat this process for all i and we will obtain the key. (You have to prove it yourself. I will not explain further and it will be an exercise for you to practice)

Source code:
```python
from pwn import remote, log, args
import struct
import hashlib
from Crypto.Cipher import AES

n = 256
q = 11777
w = 8
HOST = '116.203.41.47' if args.REMOTE else '0.0.0.0'
PORT = 4421
io = remote(HOST, PORT)

################################################################


def center(v): return min(v % q, v % q-q, key=abs)


def extract(r, d): return [2*t//q for u, t in zip(r, d) if u]


def ppoly(g): return struct.pack(f'<{n}H', *g).hex()
def pbits(g): return ''.join(str(int(v)) for v in g)
def hbits(g): return hashlib.sha256(pbits(g).encode()).digest()
def mkaes(bits): return AES.new(hbits(bits), AES.MODE_CTR, nonce=b'')


def unpoly(g: bytes): return list(struct.unpack(f'<{n}H', g))
def unbits(g: str): return list(map('01'.index, g))


def get_param():
    a = io.recvline(0).decode().split(': ')[-1]
    a = unpoly(bytes.fromhex(a))
    b = io.recvline(0).decode().split(': ')[-1]
    b = unpoly(bytes.fromhex(b))
    c = io.recvline(0).decode().split(': ')[-1]
    c = unpoly(bytes.fromhex(c))
    r = io.recvline(0).decode().split(': ')[-1]
    r = unbits(r)
    flag = bytes.fromhex(io.recvline(0).decode().split(': ')[-1])
    return a, b, c, r, flag


def request_server(ct):
    c, r = ct
    io.sendline(ppoly(c).encode())
    io.sendline(pbits(r).encode())
    return io.recvline(0)


def query(ct, idx1, idx2):
    c, r = ct
    _r = r[:]
    _r[idx1] = 0
    res1 = request_server((c, _r))
    _r = r[:]
    _r[idx2] = 0
    res2 = request_server((c, _r))

    return 1 if res1 == res2 else 0


def main():
    log.setLevel('debug')
    a, b, c, r, enc_flag = get_param()
    bits = [1]
    idx1 = r.index(1)
    with log.progress("Brutefocing bits") as LMAO:
        for idx2 in range(idx1+1, len(r)):
            if not r[idx2]:
                continue
            check = query((c, r), idx1, idx2)
            if check:
                bits.append(bits[-1])
            else:
                bits.append(int(not bits[-1]))
            LMAO.status(f"{len(bits)}/256 - {bits}")
            idx1 = idx2
        LMAO.success(str(bits))
    log.success(str(mkaes([0] + bits).decrypt(enc_flag)))
    for i in range(len(bits)):
        bits[i] = int(not bits[i])
    log.success(str(mkaes([0] + bits).decrypt(enc_flag)))



main()
io.close()
```

