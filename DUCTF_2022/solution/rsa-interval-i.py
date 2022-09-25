
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