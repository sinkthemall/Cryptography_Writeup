# KCSC 2023 Writeup
## Cryptography
### 1. CFB64
```python
import time
import sys
import os
from Crypto.Cipher import AES

flag = os.environ.get("FLAG", b"KCSC{FAKE_FLAGGGGGGGGGGGGGGGGGGGGGG}")

key = os.urandom(16)
iv = os.urandom(16)

def encrypt(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=64)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

print(f'encrypted_flag = {encrypt(key, iv, flag).hex()}')

for _ in range(23):
    plaintext = bytes.fromhex(input("plaintext: "))
    print(f'ciphertext = {encrypt(key, iv, plaintext).hex()}')
```
In this challenge, we encounter an oracle: the data we send is encrypted in AES CFB MODE with segment size is 8 byte. For who don't know, CFB MODE is a stream cipher, which mean the plaintext is XOR with the keystream generated by block cipher, so the main idea to leak flag is to send null bytes --> This will reveal the keystream and then we can use that keystream to recover flag.
Solution:
```python
from pwn import *
s = remote("188.166.220.129", 60124)


s.recvuntil(b"encrypted_flag = ")
enc = bytes.fromhex(s.recvline(0).decode())


def xor(a,b):
    return bytes([ i ^ j for i,j in zip(a,b)])

flag = b""

for i in range(6):
    payload = flag + b"\x00" * 8
    s.sendline(payload.hex().encode())
    s.recvuntil(b"ciphertext = ")
    lmao = bytes.fromhex(s.recvline(0).decode())
    flag += xor(enc[8 * i: 8*(i + 1)], lmao[8*i : 8*(i+1)])
    print(xor(lmao, enc))
    print("found flag:", flag)


print(flag)
```
### 2. OLCG
```go
package main

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"strconv"
)

func main() {
    fmt.Println(" _  __  ___  ___   ___   _      ___   _____  _____  ___  ___ __  __ ")
    fmt.Println("| |/ / / __|/ __| / __| | |    / _ \\ |_   _||_   _|| __|| _ \\\\ \\ / / ")
    fmt.Println("| ' < | (__ \\__ \\| (__  | |__ | (_) |  | |    | |  | _| |   / \\ V /  ")
    fmt.Println("|_|\\_\\ \\___||___/ \\___| |____| \\___/   |_|    |_|  |___||_|_\\  |_|   ")
	fmt.Println()
	
	var a,b,c,d,e,y,m int
	m = 1<<31 - 1
	a = rand.Intn(m)
	b = rand.Intn(m)
	c = rand.Intn(m)
	d = rand.Intn(m)
	e = rand.Intn(m)
	y = rand.Intn(m)

	fmt.Println("I will give u 5 lucky numbers :>")
	for i:=1; i<=5; i++ {
		y = (a*d + b*e + c) % m
		fmt.Printf("Lucky number %v: %v \n", i, y)
		e = d
		d = y
	}
	fmt.Println()

	fmt.Println("Now show off your guessing skills, ego ._.")
	var guess string
	for i:=1; i<=23; i++ {
		y = (a*d + b*e + c) % m
		fmt.Print("Guess: ")
		fmt.Scan(&guess)
		numGuess, _ := strconv.Atoi(guess)
		if numGuess == y {
			fmt.Printf("Nai xuw !!! Remain: %v/23\n", 23-i)
		} else {
			fmt.Println("Luck is only for those who try, if you don't understand that, then get out !!!")
			return
		}
		e = d
		d = y
	}

	fmt.Println("WOW, I rly want know how do u can guess all correctly, plz sharing w me :<")
	content, _ := ioutil.ReadFile("flag.txt")
	fmt.Println(string(content))
}
```
This challenge is  a modified version of LCG (Linear congurence generator) : Given sequence of 5 number which are result from modified LCG, our task is to predict it 23 times in order to get the flag. Again, this challenge is not really hard: Let's call our sequence are ```y1, y2, y3, y4, y5```. Subtract ``` y3 and y4```, we will get: ```a.(y1 - y2) + b(y2 - y3) = y3 - y4```, also ```y4 and y5``` we also get: ```a.(y2 - y3) + b(y3 - y4) = y4 - y5```. You might see the way to calculate a and b. That's right: matrix. Because the challenge reuse the data( which is not really a good idea as it make the challenge less fun), so it reduce our task to calculate a and b.

Solution:
```python
from pwn import *
s = remote("188.166.220.129", int(60123))
p = (1<<31) - 1
y = [1193586604, 90851867, 1072153267, 1582222533, 457737674]
a, b = 1298498081, 2019727887

c = (y[2] - (int(a * y[1] + b * y[0]) % p)) % p

e = y[3]
d = y[4]
for i in range(23):
    s.recvuntil(b"Guess: ")
    ok = (a * d + b * e + c) % p
    s.sendline(str(ok).encode())
    msg = s.recvline(0).decode()
    if "Nai xuw !!!" in msg:
        print("Sucess")
    else:

        print("Failed")
        exit(0)

    e = d
    d = ok
s.interactive()
```

### 3. ECDSAAAA
```javascript
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        System.out.println(publicKey);

        System.out.println("############################################# SIGN #############################################");
        Scanner sc = new Scanner(System.in);
        System.out.print("Enter msg: ");
        String msg = sc.nextLine();
        if (msg.equals("Hi im Gan Dam")) {
            System.out.println("Go to airport :<");
            System.exit(0);
        }
        String base64Ssignature = sign(msg, privateKey);
        System.out.printf("Signature: %s \n", base64Ssignature);

        System.out.println("############################################# VERIFY #############################################");
        System.out.print("Enter msg: ");
        String msgV = sc.nextLine();
        System.out.print("Enter signature: ");
        String signV = sc.nextLine();
        if (verify(msgV, signV, publicKey)) {
            if (msgV.equals("Hi im Gan Dam")) {
                System.out.println("KCSC{fake_flaggggggggggggggggggggg}");
            } else {
                System.out.println("Go to airport :<");
                System.exit(0);
            }
        } else {
            System.out.println("Go to airport :<");
            System.exit(0);
        }
    }

    public static String sign(String msg, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA512withECDSAinP1363Format");
        signature.initSign(privateKey);
        signature.update(msg.getBytes("UTF-8"));
        String base64Ssignature = Base64.getEncoder().encodeToString(signature.sign());
        return base64Ssignature;
    }

    public static boolean verify(String msg, String base64Ssignature, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance("SHA512withECDSAinP1363Format");
        verifier.initVerify(publicKey);
        verifier.update(msg.getBytes("UTF-8"));
        byte[] signature = Base64.getDecoder().decode(base64Ssignature);
        return verifier.verify(signature);
    }
}
```
Because I did not capture the solution(I didnt use script to solve), so I will explain what I did to solve it. The idea from this challenge is actually taken from ```CVE-2022-21449```. It related to a bug where ecdsa implemenation in javascript does not check the validity of the signature, where user could input r s are all zero => This make our point P_k = (0,0) - the infinity point( because P_k is infinity point, therefore the signature is invalid, but javascript doesn't check this and consider it as a valid signature) => This one make any message become valid with signature r = 0, s =0 - the key idea to bypass.

### 4. CRC64
```python
import secrets
import time
import sys
import os

flag = os.environ.get("FLAG", "KCSC{FAKE_FLAGGGGGGGGGGGGGGGGGGGGGG}")
key = secrets.randbits(64)

def crc64(data: bytes, init: int) -> int:
    g = 0xcd8da4ff37e45ec3
    crc = init

    for x in data:
        crc = crc ^ x
        for _ in range(8):
            crc = ((crc >> 1) ^ (g * (crc & 1))) & 0xffffffffffffffff
    return crc


def auth(code: int, t: int) -> bool:
    return crc64((key ^ t).to_bytes(8, "little"), code) == code

while True:
    print("[A]uthenticate yourself")
    print("[H]int for pre-shared key")
    choice = input("> ").strip()
    if choice == "A":
        code = int(input("code: "), 16)
        assert 0 <= code < 2**64

        # key is changed in every 5 seconds
        t = int(time.time()) // 5 * 5
        if auth(code, t):
            print(flag)
            sys.exit(0)
        print("WRONG code")

    elif choice == "H":
        t = int(time.time()) // 5 * 5
        hint = crc64(b"hint", crc64((key ^ t).to_bytes(8, "little"), 0))
        print(f"hint: {hint:x}")

    else:
        sys.exit(0)
```
SECCON CTF 2022 Finals - authenticator problem ????

I think there must be MD5 collision in here :D.

In order to do this challenge, I used ```Sagemath``` for solving . Define the polynomial ```f = X``` as the secret we need to find, the modulus polynomial is ```mod = x^64 + PR(g)``` with ```PR(g)``` correspond to the polynomial with ```g``` as the coefficient. Then the shift left operator by 1 is actually multiply by x, xor is sum of polynomials,... After that, redefine the crc64 function to sagemath version and use f.roots() to find the solution => secret recover.

```python
from pwn import remote, process
import time
from sage.all import *

HOST = "188.166.220.129"
PORT = 60125
k = 64
PR = GF(2)['x']
(x,) = PR.gens()
g = PR(list(map(int, f"{0xcd8da4ff37e45ec3:064b}"))) + x**64
n = g.degree()
PPR = PolynomialRing(PR.quotient(g), names=('X',))
(X,) = PPR.gens()


def int_to_poly(x):
    return PR(Integer(x).bits())


def poly_to_int(p):
    return Integer(p.list(), 2)


def reverse_poly(p, size):
    ls = p.list()
    return PR((ls + [0] * (size - len(ls)))[::-1])


def crc(msg: bytes, init: int =0, n=32):
    assert (msg is not None) or (init is not None), "Need at least 1 argument!"
    is_equaltion = False
    if msg is None:
        k = n
        is_equaltion = True
        H = X
    else:
        k = len(msg) * 8
        H = reverse_poly(int_to_poly(int.from_bytes(msg, "little")), k)
    if init is None:
        is_equaltion = True
        Init = X
    else:
        Init = reverse_poly(int_to_poly(init), n)
    f = H * x**n + Init * x**k
    if not is_equaltion:
        return poly_to_int(reverse_poly(f % g, n))
    return f


io = remote(HOST, int(PORT))
# io = process(["python", "chall.py"])

# get hint
io.sendlineafter(b"> ", b"H")
t = int(time.time()) // 5 * 5
io.recvuntil(b"hint: ")
hint = int(io.recvline(0), 16)



# hint = crc("hint", Prev)
data = b"hint"
f = crc(data, None, 64) - reverse_poly(int_to_poly(hint), k)
Prev = f.roots()[0][0]
print(f"Prev crc of hint: {hex(poly_to_int(reverse_poly(Prev, 64)))}")


# Find Key
# Prev = crc(Key^t, 0)
poly_0 = reverse_poly(int_to_poly(0), n)
f = crc(None, 0, 64) - Prev  # reverse_poly(Prev) = reverse_poly(X*x**n)
Kt = poly_to_int(reverse_poly(f.roots()[0][0], k))
K = Kt ^ t
print("Key:", hex(K))


# Find code
t = int(time.time()) // 5 * 5
f = crc(int(K ^ t).to_bytes(8, 'little'), None, 64) - X
code = poly_to_int(reverse_poly(f.roots()[0][0], k))
print("Authenticate input:", hex(code))



assert crc(int(K ^t).to_bytes(8, 'little'), code, 64) == code
io.sendlineafter(b"> ", b"A")
io.sendlineafter(b": ", hex(code)[2:].encode())
print(io.recv().decode())
```