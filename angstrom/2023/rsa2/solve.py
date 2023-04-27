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