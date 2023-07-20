## zer0pts CTF 2023 Writeup
### 1. easy_factoring
```python
import os
import signal
from Crypto.Util.number import *

flag = os.environb.get(b"FLAG", b"dummmmy{test_test_test}")

def main():
    p = getPrime(128)
    q = getPrime(128)
    n = p * q

    N = pow(p, 2) + pow(q, 2)

    print("Let's factoring !")
    print("N:", N)

    p = int(input("p: "))
    q = int(input("q: "))

    if isPrime(p) and isPrime(q) and n == p * q:
        print("yey!")
        print("Here you are")
        print(flag)
    else:
        print("omg")

def timeout(signum, frame):
    print("Timed out...")
    signal.alarm(0)
    exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(30)
    main()
    signal.alarm(0)

```

Solution: I use [this](https://www.alpertron.com.ar/TSQCUBES.HTM) to factoring N.

### 3. SquareRNG
```python
#!/usr/bin/env python3
import os
from Crypto.Util.number import getPrime, getRandomRange

def isSquare(a, p):
    return pow(a, (p-1)//2, p) != p-1

class SquareRNG(object):
    def __init__(self, p, sa, sb):
        assert sa != 0 and sb != 0
        (self.p, self.sa, self.sb) = (p, sa, sb)
        self.x = 0

    def int(self, nbits):
        v, s = 0, 1
        for _ in range(nbits):
            self.x = (self.x + 1) % p
            s += pow(self.sa, self.x, self.p) * pow(self.sb, self.x, self.p)
            s %= self.p
            v = (v << 1) | int(isSquare(s, self.p))
        return v

    def bool(self):
        self.x = (self.x + 1) % self.p
        t = (pow(self.sa, self.x, self.p) + pow(self.sb, self.x, self.p))
        t %= self.p
        return isSquare(t, self.p)

p = getPrime(256)

sb1 = int(input("Bob's seed 1: ")) % p
sb2 = int(input("Bob's seed 2: ")) % p
for _ in range(77):
    sa = getRandomRange(1, p)
    r1 = SquareRNG(p, sa, sb1)
    print("Random 1:", hex(r1.int(32)))
    r2 = SquareRNG(p, sa, sb2)
    print("Random 2:", hex(r2.int(32)))

    guess = int(input("Guess next bool [0 or 1]: "))
    if guess == int(r1.bool()):
        print("OK!")
    else:
        print("NG...")
        break
else:
    print("Congratz!")
    print(os.getenv("FLAG", "nek0pts{*** REDACTED ***}"))
```

To solve this challenge, we first need to input ```sb1, sb2``` such that it can use to predict number. When first thinking the idea, I notice 3 special numbers: ```1, -1, 0```. We cannot input 0, as it will raise the exception. So, only 2 other options remain. After that, I analysis what can be exploit with 2 random sequence that challenge gave us: ```r1 and r2```. 


Here is the output when we input -1:
```
bit 0 : 1 + a
bit 1 : 1 + a + a^2
bit 2 : 1 + a + a^2 + a^3
bit 3 : 1 + a + a^2 + a^3 + a^4
...
bit 31 : 1 + a^2 + ... + a^32
```
when we are asked to predict the next number, it will be : ```a^33 + 1(1)```
Here is the output when we input -1:
```
bit 0 : 1 - a
bit 1 : 1 - a + a^2
bit 2 : 1 - a + a^2 - a^3
bit 3 : 1 - a + a^2 - a^3 - a^4
...
bit 31 : 1 - a + a^2 - ... + a^32
```
When we are asked to predict the next number, it will be : ```a^33 - 1(2)```
In case (1), the equation can be factored into : ```a^33 + 1(1) = (a + 1).(a^32 - a^31 + a^30 - ... + 1)```
In case (2), the equation can be factored into : ```a^33 - 1(2) = (a - 1).(a^32 + a^31 + a^30 + ... + 1)```
If ```a+1``` is a square number (we can  confirm that by ```r1 and r2```), and ```a^32 - a^31 + a^30 - ... + 1``` is also s square number, we can conclude that the result of ```a^33 + 1``` is also square number. If one of them is, but the other not, then it can never be a square number. I'm not sure about the case 2 of them are not square number( sometimes, it can be the case where both of them are not square number, but the product is the square number), but the chance is small.

Source (this one was from my friend [vnc](https://github.com/idk-wh0am1)):
```python
from pwn import *
from Crypto.Util.number import *

context.log_level = 'debug'
# 1 + a + a^2 + a^3 + ... + a^32
# 1 - a + a^2 - a^3 + ... + a^32

def solve():
    io.recvuntil(b"Random 1: "); r1 = int(io.recvline(), 16)
    io.recvuntil(b"Random 2: "); r2 = int(io.recvline(), 16)

    ans = int((r1 >> 31) ^ (r2 & 1) == 0)
    io.sendlineafter(b": ", str(ans).encode())
io = remote("crypto.2023.zer0pts.com", 10666)

io.sendlineafter(b"Bob's seed 1: ", b"1")
io.sendlineafter(b"Bob's seed 2: ", b"-1")

for _ in range(77):
    solve()

io.interactive()
```