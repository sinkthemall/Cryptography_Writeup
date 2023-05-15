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