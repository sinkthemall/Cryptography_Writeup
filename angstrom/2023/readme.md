# AngstromCTF Writeup
## Cryptography
### 1. Ranch
Simple Caesar cipher, a little bit work and we can recover the flag
```python
import string
def enc(encr, shift):
    encrypted = ""
    for i in encr:
        if i in string.ascii_lowercase:
            encrypted += chr(((ord(i) - 97 + shift) % 26)+97)
        else:
            encrypted += i


    print(encrypted)
encr = "rtkw{cf0bj_czbv_nv'cc_y4mv_kf_kip_re0kyvi_uivjj1ex_5vw89s3r44901831}"
for i in range(26):
    enc(encr, i)
```
Flag : ```actf{lo0ks_like_we'll_h4ve_to_try_an0ther_dress1ng_5ef89b3a44901831}```

### 2. Royal Society of Art
```python
from Crypto.Util.number import getStrongPrime, bytes_to_long
f = open("flag.txt").read()
m = bytes_to_long(f.encode())
p = getStrongPrime(512)
q = getStrongPrime(512)
n = p*q
e = 65537
c = pow(m,e,n)
print("n =",n)
print("e =",e)
print("c =",c)
print("(p-2)*(q-1) =", (p-2)*(q-1))
print("(p-1)*(q-2) =", (p-1)*(q-2))
```
if we subtract ```(p-2) * (q-1)``` with ```(p-1) * (q-2)```, we will get ```p - q```. Using this with n = p * q to recover the whole flag

Solution:
```python
from gmpy2 import iroot
n = 125152237161980107859596658891851084232065907177682165993300073587653109353529564397637482758441209445085460664497151026134819384539887509146955251284230158509195522123739130077725744091649212709410268449632822394998403777113982287135909401792915941770405800840172214125677106752311001755849804716850482011237
e = 65537
c = 40544832072726879770661606103417010618988078158535064967318135325645800905492733782556836821807067038917156891878646364780739241157067824416245546374568847937204678288252116089080688173934638564031950544806463980467254757125934359394683198190255474629179266277601987023393543376811412693043039558487983367289
p2q1 = 125152237161980107859596658891851084232065907177682165993300073587653109353529564397637482758441209445085460664497151026134819384539887509146955251284230125943565148141498300205893475242956903188936949934637477735897301870046234768439825644866543391610507164360506843171701976641285249754264159339017466738250
p1q2 = 125152237161980107859596658891851084232065907177682165993300073587653109353529564397637482758441209445085460664497151026134819384539887509146955251284230123577760657520479879758538312798938234126141096433998438004751495264208294710150161381066757910797946636886901614307738041629014360829994204066455759806614
pq = p2q1 - p1q2
def solve():
    
    delta = pq ** 2 + 4*n
    d, F = iroot(delta, 2)
    if not F:
        return -1,-1
    else:
        p = (-pq + d)//2
        q = n // p
        return p, q
    

p, q = solve()
print(p,q)

assert(p*q == n)
d =  pow(e, -1, (p-1)*(q-1))
from Crypto.Util.number import long_to_bytes
print(long_to_bytes(pow(c, d, n)))
```
Flag: ```actf{tw0_equ4ti0ns_in_tw0_unkn0wns_d62507431b7e7087}```
### 3. Royal Society of Art 2
```python
from Crypto.Util.number import getStrongPrime, bytes_to_long, long_to_bytes
f = open("flag.txt").read()
m = bytes_to_long(f.encode())
p = getStrongPrime(512)
q = getStrongPrime(512)
n = p*q
e = 65537
c = pow(m,e,n)
print("n =",n)
print("e =",e)
print("c =",c)

d = pow(e, -1, (p-1)*(q-1))

c = int(input("Text to decrypt: "))

if c == m or b"actf{" in long_to_bytes(pow(c, d, n)):
    print("No flag for you!")
    exit(1)

print("m =", pow(c, d, n))
```
This challenge have a tricky way to recover the flag. If we send ```(2*m)**e```, the decrypt we receive will be ```2*m1```, which doesnt have ```actf{```. Multiplying that with ```2**-1 (mod n)``` and we can recover the full flag.

Solution:
```python
from pwn import *
s = remote('challs.actf.co', 32400)
s.recvuntil(b"n = ")
n = int(s.recvline()[:-1].decode())
s.recvuntil(b"e = ")
e = int(s.recvline()[:-1].decode())
s.recvuntil(b"c = ")
c = int(s.recvline()[:-1].decode())

newc = (c * pow(2, e, n))
s.sendlineafter(b"Text to decrypt: ", str(newc).encode())
s.recvuntil(b"m = ")

m = int(s.recvline()[:-1].decode())
from Crypto.Util.number import long_to_bytes
print(long_to_bytes(m // 2))
```
Flag:```actf{rs4_is_sorta_homom0rphic_50c8d344df58322b}```
### 4. LazyLagrange
```python
#!/usr/local/bin/python
import random

with open('flag.txt', 'r') as f:
	FLAG = f.read()

assert all(c.isascii() and c.isprintable() for c in FLAG), 'Malformed flag'
N = len(FLAG)
assert N <= 18, 'I\'m too lazy to store a flag that long.'
p = None
a = None
M = (1 << 127) - 1

def query1(s):
	if len(s) > 100:
		return 'I\'m too lazy to read a query that long.'
	x = s.split()
	if len(x) > 10:
		return 'I\'m too lazy to process that many inputs.'
	if any(not x_i.isdecimal() for x_i in x):
		return 'I\'m too lazy to decipher strange inputs.'
	x = (int(x_i) for x_i in x)
	global p, a
	p = random.sample(range(N), k=N)
	a = [ord(FLAG[p[i]]) for i in range(N)]
	res = ''
	for x_i in x:
		res += f'{sum(a[j] * x_i ** j for j in range(N)) % M}\n'
	return res

query1('0')

def query2(s):
	if len(s) > 100:
		return 'I\'m too lazy to read a query that long.'
	x = s.split()
	if any(not x_i.isdecimal() for x_i in x):
		return 'I\'m too lazy to decipher strange inputs.'
	x = [int(x_i) for x_i in x]
	while len(x) < N:
		x.append(0)
	z = 1
	for i in range(N):
		z *= not x[i] - a[i]
	return ' '.join(str(p_i * z) for p_i in p)

while True:
	try:
		choice = int(input(": "))
		assert 1 <= choice <= 2
		match choice:
			case 1:
				print(query1(input("\t> ")))
			case 2:
				print(query2(input("\t> ")))
	except Exception as e:
		print("Bad input, exiting", e)
		break
```
I will assume that you read and understand what is the problem in here. So my way to bypass this is by sending x = 127 to the server. In case you don't know, the flag length is 18-byte long. And ```127**18 - 1 < (1<<127) - 1``` , which mean, we can transform the sum we receive into 127-base . Each number will represent a character in a flag. That will solve the problem. Using this information to get the order of each character and we can recover full flag.
Solution:
```python
from pwn import *
s = remote('challs.actf.co', 32100)

s.sendlineafter(b": ", b"2")
s.sendlineafter(b"> ", b"1")
L = len(list(s.recvline()[:-1].decode().split()))
print(L)
s.sendlineafter(b": ", b"1")
s.sendlineafter(b"> ", b"127")

res = s.recvline()[:-1].decode()
print(res)
res = int(res)


def get_x_state(sum):
    ans = []
    for i in range(L):
        last = sum % 127 
        ans.append(last)
        sum //= 127 
    return ans

x = get_x_state(res)
print(" ".join(str(i) for i in x))
print(bytes(x))
s.sendlineafter(b": ", b"2")
s.sendlineafter(b"> ", (" ".join(str(i) for i in x)).encode())
p = s.recvline()[:-1].decode().split()
newp = [int(i) for i in p]
flag = [0 for i in range(L)]
print(newp)
for i, char in zip(newp, x):
    flag[i] = char

print(bytes(flag))
```
Flag:```actf{f80f6086a77b}```

## Pwn

Recently, I am interested in exploiting. That's why I do not only write cryptography writeup, but also pwn. Solve total 4/7. I will not explain detail about the challenge (as it take lots of time to do, and I am a lazy person :3 ), but I will upload all the solutions.

Solved:
1. queue
2. gaga
3. leek
4. widget

## Reverse engineering
### Wordsearch
I actually help my teamate solve 1 of RE challenge ( not sure about that :D ), for more detail about RE writeup, please read [this readme](https://github.com/lephuduc/CTFs-Honors/tree/main/AngstromCTF-2023) from [Jinn](https://github.com/lephuduc)
My solution:
```python
enc = "(kh)k'k(Qj)Q'Q(2U)2'2(35)3'3(Ff)F(ul)u?hbjU5?'F(9M)9'9(4 C)4'4(iv)i?ofM?'u?tCl?(SP)S'S'i?Pvh?_(k4)k'k(Q0)Q'Q(2Y)2'2(9 j)9'9(uB)u(S I)S(N7)N(oH)o?40Yi?(3a)3'3(Fi)F'F'S(XG)X'o?arij?(4k)4'4'u(fs)f(d f)d?kBr?(ix)i'i'X(cH)c'd(VZ)V(q x)q'q(DJ)D(W B)W?eIxG?(sp)s's(xN)x'x(pD)p'p'N'W?pND7g?(Mq)M'M?uqH?'c'f'V?HsfZl?'D(eT)e'e(j N)j'j?xJaT??BNr?_(kh)k'k(QS)Q'Q(2U)2'2(32)3'3(FZ)F(4s)4(XG)X?hSaU2?'F(97)9'9'4(Sw)S'S?nZ7s?(uc)u'u(iQ)i'i'X?cdwQG?_(k6)k'k(Qq)Q'Q(F8)F(9 8)9(i v)i(e4)e?i6q?(2t)2'2(3i)3'3'F'9(4 u)4'4(p R)p(oK)o(f b)f(Vr)V(D8)D?tin8?(us)u'u(SF)S'i(X 1)X'X(sS)s(NR)N(c 9)c(q o)q?8eus?'S'p(M X)M'f(W f)W(jm)j?Fvx1?'s(xo)x'x'c?Sop?'M'e'j?rR?'N(d8)d?eRX?'o?sK9?'d'q'W?sb8?'V?iro?'D?8v4??efm?"
flag = ""
if '[' in enc or ']' in enc:
    print("[] found")
if '*' in enc:
    print("* found")
if "." in enc:
    print(". found")
flag = []
temp = ['\x00' for i in range(128)]

def extract_key():
    i = 0
    lmao1 = []
    lmao2 = []
    while i < len(enc):

        if enc[i] == "(":
            tag = enc[i + 1]
            first = i + 2
            while enc[i] != ")":
                i += 1
            if i - first == 1:
                temp[ord(tag)] = enc[first]
            else:
                temp[ord(tag)] = enc[i-1]
                pass
        elif enc[i] == "'":
            tag = enc[i + 1]
            i += 1
            lmao2.append(temp[ord(tag)])

            pass
        elif enc[i] == " ":
            pass

        elif enc[i] == "?":
            i += 1
            while enc[i] != "?":
                lmao1.append(enc[i])
                i += 1
            for j in lmao1:
                if not (j in lmao2) and (j not in "0123456789"):
                    flag.append(j)
                    lmao2 = []
                    lmao1 = []
                    break
       #     flag.append()
        elif enc[i] == "_":
            flag.append("_")
            pass
        i += 1
suspicious = "(Ff)F(ul)u?hbjU5?'F"
debug_this_shit= "(ul)u?hbjU5?"
extract_key()
print("".join(flag))
```
You will receive something that is not look like the flag. The reason for this is there are some distracting character confusing the English word, so I search google some word that have the same pattern and just print out the flag.
Flag:```actf{both_irregular_and_inexpressive}```
