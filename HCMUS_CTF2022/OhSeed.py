from pwn import remote
from randcrack import RandCrack

rc = RandCrack()
r = remote("103.245.250.31", 30620)
res = r.recvuntil(b"guess the last random number:\n").decode().split('\n')[2].strip()
leak = [int(i) for i in res.split(' ')]
print(leak)
for i in range(624):
	rc.submit(leak[i])
	# Could be filled with random.randint(0,4294967294) or random.randrange(0,4294967294)

for i in range(665 - 624):
    print(f"Leak: {leak[624 + i]}")
    print("Cracker result: {}".format(rc.predict_randrange(0, 4294967295 - 2)))
    print("*"*20)
ans = rc.predict_randrange(0, 4294967295 - 2)
print("Cracker result: {}".format(ans))
r.sendline(str(ans).encode())

r.interactive()
