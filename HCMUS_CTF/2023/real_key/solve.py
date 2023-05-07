import numpy as np
from scipy.optimize import differential_evolution
f = open("d:\\output.txt")
ys = eval(f.read())

ys = np.array(ys)
N = 1600
T = 1/800
bounds = [(0, 255)] * 4
x = np.array(np.linspace(0, N*T, N))
f = ys
print(f[0])
def ok(row):
    """Make the key wavy"""
    N = 1600
    T = 1/800
    x = np.linspace(0, N*T, N)
    ys = np.sum(np.array([.5**i * np.sin(n * 2 * np.pi * x) for i, n in enumerate(row)]), axis=0).tolist()
    return ys

def objective_func(a, q):
    ys = ok(a)
    return np.sum((ys - q) ** 2)

key = []
ook = [[241.,  62.,  82., 133.],
[193., 113.,  73., 146.],
[144., 107., 159.,  97.],
[241., 220., 127.,  68.]]
for i in ook:
    for j in i :
        key.append(int(j))
# for q in f:
#     result = differential_evolution(objective_func, bounds, args = (q, ))
#     print(result.x)
#     for i in result.x:
#         key.append(int(i))

from Crypto.Cipher import AES 
key = bytes(key)
lmao = open("d:\\ciphertext.bin", "rb")
iv = lmao.read(16)
enc = lmao.read()
cipher = AES.new(key, AES.MODE_CBC, iv)



print("decrypt flag:", cipher.decrypt(enc))