from pwn import *
s = remote('challs.actf.co', 32100)

s.sendlineafter(b": ", b"2")
s.sendlineafter(b"> ", b"1")
L = len(list(s.recvline()[:-1].decode().split()))
print(L)
s.sendlineafter(b": ", b"1")
s.sendlineafter(b"> ", b"127")

res = s.recvline()[:-1].decode()
print(res)
res = int(res)


def get_x_state(sum):
    ans = []
    for i in range(L):
        last = sum % 127 
        ans.append(last)
        sum //= 127 
    return ans

x = get_x_state(res)
print(" ".join(str(i) for i in x))
print(bytes(x))
s.sendlineafter(b": ", b"2")
s.sendlineafter(b"> ", (" ".join(str(i) for i in x)).encode())
p = s.recvline()[:-1].decode().split()
newp = [int(i) for i in p]
flag = [0 for i in range(L)]
print(newp)
for i, char in zip(newp, x):
    flag[i] = char

print(bytes(flag))

