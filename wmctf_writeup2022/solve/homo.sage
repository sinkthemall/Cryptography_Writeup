pk = eval(open("pubkey.txt").read())
ct = eval(open("cipher.txt").read())
def acd_attack(x, rho):
    R = 2^rho 
    B = [[0 for i in range(len(x))] for j in range(len(x))]
    B[0][0] = R 
    for i in range(1, len(x)):
        B[0][i] = x[i]
        B[i][i] = -x[0]
    B = Matrix(B)
    for i in B.LLL():
        if (i[0] != 0) and (i[0] %R == 0):
            return abs(i[0]//R)

q0 = acd_attack(pk[:7], 192)
print(q0)
from Crypto.Util.number import isPrime, long_to_bytes
sk_approx = (pk[0] // q0) - (2^191)//q0
print(sk_approx)
print(int(sk_approx).bit_length())
sk_approx += 1
flag = "".join(str((i%sk_approx)%2) for i in ct)
flag = int(flag, 2)
print(long_to_bytes(flag))


