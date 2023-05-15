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