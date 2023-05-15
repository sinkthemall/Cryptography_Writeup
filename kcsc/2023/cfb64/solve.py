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
