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

        