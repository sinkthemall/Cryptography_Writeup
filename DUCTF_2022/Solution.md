# DUCTF 2022 Writeup - Cryptography
DUCTF was the first CTF I played when I started to learn hacking, and it was terrible, as I didn't solve any problems. But that was where everything was started. And now, this revisiting was much better. I solved 4 out of 11 problems. DUCTF this year was much harder than the last year, and I have learned a lot of thing after all. Even this time, i didnt make too much progress, but I still want to post my writeup so as to share with you how I managed to solve these problems, and to prove that I have learned and become stronger than myself last year !!!
### Baby arx
```python
class baby_arx():
    def __init__(self, key):
        assert len(key) == 64
        self.state = list(key)

    def b(self):
        b1 = self.state[0]
        b2 = self.state[1]
        b1 = (b1 ^ ((b1 << 1) | (b1 & 1))) & 0xff
        b2 = (b2 ^ ((b2 >> 5) | (b2 << 3))) & 0xff
        b = (b1 + b2) % 256
        self.state = self.state[1:] + [b]
        return b

    def stream(self, n):
        return bytes([self.b() for _ in range(n)])


FLAG = open('./flag.txt', 'rb').read().strip()
cipher = baby_arx(FLAG)
out = cipher.stream(64).hex()
print(out)

# cb57ba706aae5f275d6d8941b7c7706fe261b7c74d3384390b691c3d982941ac4931c6a4394a1a7b7a336bc3662fd0edab3ff8b31b96d112a026f93fff07e61b

```
In the first problem, the problem give us an encrypted flag. Initially, the class ```baby_arx``` receive flag as the key to create stream. To understand more about it, let's have a look closer at this code
```python
        b1 = self.state[0]
        b2 = self.state[1]
        b1 = (b1 ^ ((b1 << 1) | (b1 & 1))) & 0xff
        b2 = (b2 ^ ((b2 >> 5) | (b2 << 3))) & 0xff
        b = (b1 + b2) % 256
        self.state = self.state[1:] + [b]
        return b
```
So we notice that in b() function, it takes two bytes from current states : ```state[0]``` and ```state[1]```. Then it do some xor and shift operation to create b1 and b2. Finally, it sum up those number to create the new last state number ```self.state = self.state[1:] + [b]```. This was actually easy to solve, because it take the current state to encrypt, and we already know that the last character of flag is "}". So, we can calculate b2 and reverse the code to find b1 - or even the character which was encrypted to b1.
Code:
```python
enc = bytes.fromhex('cb57ba706aae5f275d6d8941b7c7706fe261b7c74d3384390b691c3d982941ac4931c6a4394a1a7b7a336bc3662fd0edab3ff8b31b96d112a026f93fff07e61b')
las = ord('}')
dec = '}'
def find_b1(state):
    for b1 in range(128):
        if ((b1 ^ ((b1 << 1) | (b1 & 1))) & 0xff) == state:
            return b1
    return -1

def find_b2(state):
    for b2 in range(128):
        if ((b2 ^ ((b2 >> 5) | (b2 << 3))) & 0xff) == state:
            return b2

for b in enc[:-1][::-1]:
    b2 = (las ^ ((las >> 5) | (las << 3))) & 0xff
    b1 = (b - b2)%256
    las = find_b1(b1)
    dec += chr(las)
print(dec[::-1])
```
### oracle for block cipher enthusiasts
```python
#!/usr/bin/env python3

from os import urandom, path
from Crypto.Cipher import AES


FLAG = open(path.join(path.dirname(__file__), 'flag.txt'), 'r').read().strip()
MESSAGE = f'Decrypt this... {urandom(300).hex()} {FLAG}'


def main():
    key = urandom(16)
    for _ in range(2):
        iv = bytes.fromhex(input('iv: '))
        aes = AES.new(key, iv=iv, mode=AES.MODE_OFB)
        ct = aes.encrypt(MESSAGE.encode())
        print(ct.hex())


if __name__ == '__main__':
    main()

```
This time, we encounter by an oracle challenge(not really, cuz you can only send the message to server twice). We can chose the iv and it will give us the encryption of message( contain the flag). The cipher used here is AES OFB MODE. To solved this problem, we must know how excatly OFB MODE work. You can check out by visit this [link]https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

So know, i will guess that you know some basic about OFB MODE. And to solved this challenge, let's have a look at this
```
block 1            | block 2               | block 3            
E(iv) xor P1         E(E(iv)) xor P2         E(E(E(iv))) xor P3
```
Because we allready know the first block of MESSAGE, we could easily find the E(iv) of the first block. If you notice, by sending the E(iv) to server, you will have some encrypt message look like this.
```
block 1            | block 2               | block 3            
E(E(iv)) xor P1      E(E(E(iv))) xor P2      E(E(E(E(iv)))) xor P3
```
Do you see that? YES. By sending E(iv) in the second time, we definitely have encrypt message which use the same xor-stream (except for the first block). And by xor 2 encrypted message together, we will have this:
```
block 1     | block 2      | block 3 
P1            P1 xor P2      P2 xor P3 ...
```
Because we already know the first block, we could find P2, then P3,... the whole message by xoring them together.
Source:
```python
from pwn import *
from random import randbytes
def xor(a,b):
    return bytes([i^j for i,j in zip(a,b)])

def solve_flag():
    flag = b"Decrypt this... "
    s = remote('2022.ductf.dev', 30009)
    iv1 = randbytes(16)
    s.sendlineafter(b'iv: ', iv1.hex().encode())
    enc = bytes.fromhex(s.recvline().decode()[:-1])
    iv2 = xor(flag[-16:], enc[len(flag) - 16 : len(flag)])
    s.sendlineafter(b'iv: ', iv2.hex().encode())
    msg = bytes.fromhex(s.recvline().decode()[:-1])
    msg = xor(msg, enc[16:])
    l = 0
    while True:

        flag += xor(flag[-16:], msg[l : ])
        l += 16
        print(flag)
        if (l > 1000):
            break

    print(flag)

solve_flag()

        
```
### rsa interval oracle i
```python
#!/usr/bin/env python3

import signal, time
from os import urandom, path
from Crypto.Util.number import getPrime, bytes_to_long


FLAG = open(path.join(path.dirname(__file__), 'flag.txt'), 'r').read().strip()

N_BITS = 384
TIMEOUT = 20 * 60
MAX_INTERVALS = 384
MAX_QUERIES = 384


def main():
    p, q = getPrime(N_BITS//2), getPrime(N_BITS//2)
    N = p * q
    e = 0x10001
    d = pow(e, -1, (p - 1) * (q - 1))

    secret = bytes_to_long(urandom(N_BITS//9))
    c = pow(secret, e, N)

    print(N)
    print(c)

    intervals = []
    queries_used = 0

    while True:
        print('1. Add interval\n2. Request oracle\n3. Get flag')
        choice = int(input('> '))

        if choice == 1:
            if len(intervals) >= MAX_INTERVALS:
                print('No more intervals allowed!')
                continue

            lower = int(input(f'Lower bound: '))
            upper = int(input(f'Upper bound: '))
            intervals.insert(0, (lower, upper))

        elif choice == 2:
            queries = input('queries: ')
            queries = [int(c.strip()) for c in queries.split(',')]
            queries_used += len(queries)
            if queries_used > MAX_QUERIES:
                print('No more queries allowed!')
                continue

            results = []
            for c in queries:
                m = pow(c, d, N)
                for i, (lower, upper) in enumerate(intervals):
                    in_interval = lower < m < upper
                    if in_interval:
                        results.append(i)
                        break
                else:
                    results.append(-1)

            print(','.join(map(str, results)), flush=True)

            time.sleep(MAX_INTERVALS * (MAX_QUERIES // N_BITS - 1))
        elif choice == 3:
            secret_guess = int(input('Enter secret: '))
            if secret == secret_guess:
                print(FLAG)
            else:
                print('Incorrect secret :(')
            exit()

        else:
            print('Invalid choice')


if __name__ == '__main__':
    signal.alarm(TIMEOUT)
    main()

```
Again, an oracle challenge, but this time, it is rsa with interval(you will know what it is).
First, it generates a secret number then encrypts with RSA cryptosystem. And then, we can either chose to add and interval with lowerbound and upperbound( it is not necessary to have lowerbound < upperbound, but why should we do that ?) or send c - encrypted number to server. After sending it, the server will decrypt (m = c^d mod n) it and check if it is in 1 of those interval we send to (lowerbound < m < upperbound). N is 384 bit_length, not actually secure enough and can be factor, but i will show you another way to solve this.

If you learned about algorithms, you know that there is an algorithm which call "Binary search". Basicaly, it is a search algorithm using spliting strategy to find a number in an interval with time complexity O(log2(N)). The idea behind this is, first, assume your number you want to find is interval (L, R). Then, let's call ```mid = (L + R)/2```, you will ask if the number is in the interval (L, mid). If it's true, you change ``` R = mid```, otherwise ```L = mid + 1```. Repeat until L = R and we found the number = L. It only takes log2(n) times to found the number, which is very fast compare to other algorithm.

So, how will we aply it into this problem? Again, assume we have an interval (0, 2^(384/9*8)) which will have the secret number. We will send c ( the secret number after encrypt) and ask if it is in the interval we just send. If true, resize the current interval(by half) containing the secret number. Repeat until L = R then we just send it to server to get the flag. It only take log2(n) times which is smaller than 384, so we can sure that it will goes well. GGEZ.

Source:
```python

from pwn import *
from Crypto.Util.number import long_to_bytes
s = remote('2022.ductf.dev', 30008)
n = int(s.recvline()[:-1].decode())
C = int(s.recvline()[:-1].decode())
print(n)
print(C)
e = 65537
l = 1
r = 2**336
ls = []
while l != r:
    s.sendlineafter(b"> ", b"1")
    mid = (l+r)//2
    s.sendlineafter(b"Lower bound: ", str(l - 1).encode())
    s.sendlineafter(b"Upper bound: ", str(mid + 1).encode())
    s.sendlineafter(b"> ", b"2")
    s.sendlineafter(b"queries: ", str(C).encode())
    ans = (s.recvline()[:-1].decode())
    print(ans)
    ans = ans.split(",")[0]
    if ans == "0":
        r = mid
    else:
        l = mid + 1
    print("bound :")
    print("L :", l)
    print("R :", r)
s.sendlineafter(b"> ", b"3")
s.sendlineafter(b'Enter secret: ', str(l).encode())
s.interactive()
```

### cheap ring theory
```python
p = 55899879511190230528616866117179357211
V = GF(p)^3
R.<x> = PolynomialRing(GF(p))
f = x^3 + 36174005300402816514311230770140802253*x^2 + 35632245244482815363927956306821829684*x + 10704085182912790916669912997954900147
Q = R.quotient(f)

def V_pow(A, n):
    return V([a^n for a in list(A)])

n, m = randint(1, p), randint(1, p)
A = Q.random_element()
B = Q.random_element()
C = A^n * B^m

print(' '.join(map(str, list(A))))
print(' '.join(map(str, list(B))))
print(' '.join(map(str, list(C))))

phi_A = V(list(map(int, input().split())))
phi_B = V(list(map(int, input().split())))
phi_C = V(list(map(int, input().split())))

check_phi_C = V_pow(phi_A, n).pairwise_product(V_pow(phi_B, m))

if phi_C == check_phi_C:
    print(open('./flag.txt', 'r').read().strip())

```
I think you need to understand some basic math for this problem( about GF) because the way you solved it is just sending ```0 0 0``` to server ( you probably gonna ask why, but that's where you need some math to know). And it means that the author doesn't restrict the input condition, which give us an easy way to solve problem ( the original method is using crt, but again, i dont know about that).
