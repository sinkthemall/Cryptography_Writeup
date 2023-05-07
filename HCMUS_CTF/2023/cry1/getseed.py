from pwn import *
import time

lmao = []
testseed = []
rseed = []

import random
# def generate_list(seed):
#     random.seed(seed)
#     return [random.randrange(1024) for i in range(26)]

# def fuck_sagemath_t_xai_z3(lmao):
    
#     solver = Solver()
#     a = [Int(f"a{i}") for i in range(26)]
#     for seed, enc in lmao:
#         ls = generate_list(seed)
#         cond = sum([ coeff * i for coeff, i in zip(a, ls)])
#         solver.add(cond == enc)
    
#     if "unsat" in solver.check():
#         print("No solution")
#     else:
#         print(solver.model())

for i in range(26):
    
    #s = process(["python3", "/mnt/d/server.py"])
    while True:
        tl = time.time()
        if round(tl, 1) - int(tl) >= 0.5:
            break
        pass
    bg = time.time()
    s = remote("cry1.chall.ctf.blackpinker.com", 443, ssl = True)
    seed = int(time.time())
    s.recvuntil(b"Here is your encoded flag: ")
    encode_flag = int(s.recvline(0).decode())
    # s.recvuntil(b"The seed is: ")
    # realseed = int(s.recvline(0).decode())
    
    s.close()
    if len(lmao) == 0 or (lmao[-1][0] != seed):
        pass
    elif lmao[-1][0] == seed and lmao[-1][1] != encode_flag:
        ok = lmao[-1][1]
        lmao[-1] = (seed - 1, ok)
    
    lmao.append((seed, encode_flag))
    testseed.append(seed)
    # rseed.append(realseed)
    ed = time.time()
    sleep(1 - (ed - bg))


print(lmao)
# print(rseed)
print(testseed)
