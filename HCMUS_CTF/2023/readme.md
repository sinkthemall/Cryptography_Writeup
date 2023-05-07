# HCMUS CTF 2023
## Cryptography
HCMUS CTF- cryptography this year is not really good, except the ```real key``` challenge, the other are not that hard (I guess because this is not the final round, so maybe it's just like an warmup. If so, I hope that in the final round there will be more interesting challenges).

### 1. Bootleg AES
So the challenge gave us 3 file, 1 bash file, 1 log file and the ciphertext file. The log file contains the result of commands in bash file writing to console. By looking at it, we know the key using to encrypt(in hex of course). But how we are gonna able to decrypt the whole file without knowing the IV?
```sh
#!/bin/bash

echo "$(cat pad.bin)$FLAG" > flag.bin
ls -alF ./pad.bin
x=$(openssl rand -hex 32)
echo $x
openssl enc -aes-256-cbc -K $x -iv $(openssl rand -hex 16) -in flag.bin -out ciphertext.bin
```
Once again, if you look closer, you might notice that the flag had been padded before encrypt, which mean that the first block might not our flag but just the padding. For who don't know, CBC actually only decrypt false on the first block if IV is wrong, but it doesn't affect to the other block. So we just need to throw some randomly IV and we can recover the flag (as we really dont care about the padding).

![Solving screen](https://github.com/sinkthemall/Cryptography_Writeup/blob/main/HCMUS_CTF/2023/bootleg_aes/solve.png)

Flag:
```HCMUS-CTF{it5-c4ll3d_pr1v4t3_k3y_crypt09raphy_f0r_4_r4350n}```
### 2. Sneak peek
```python
from Crypto.Util.number import getPrime, bytes_to_long as b2l

FLAG = b2l(b'HMCSU-CFT{SO YOU THINK THIS FLAG IS REAL\xff}')

p = getPrime(512)
q = getPrime(512)


n = p * q
peek = p >> 240

print(n)
print(peek)
print(pow(FLAG, 65537, n))
"""
137695652953436635868173236797773337408441001182675256086214756367750388214098882698624844625677992374523583895607386174643756159168603070583418054134776836804709359451133350283742854338177917816199855370966725059377660312824879861277400624102267119229693994595857701696025366109135127015217981691938713787569
6745414226866166172286907691060333580739794735754141517928503510445368134531623057
60939585660386801273264345336943282595466297131309357817378708003135300231065734017829038358019271553508356563122851120615655640023951268162873980957560729424913748657116293860815453225453706274388027182906741605930908510329721874004000783548599414462355143868922204060850666210978837231187722295496753756990
"""
```
A RSA challenge. We only know about 512 - 240 = 282 most significant bits of p, n, e and ct, so how could we decrypt with these information. The method I used here is called coppersmith (I won't explain further what is that, you should search it on your own). Let f is polynomial in Zmod(n) : f = peek * 2 ^ 240 + x, with x is variable (unknown). Because x is small( only 240 bit) we can use coppersmith to solve this equation with mod less than n.

Source:
```python
n = 137695652953436635868173236797773337408441001182675256086214756367750388214098882698624844625677992374523583895607386174643756159168603070583418054134776836804709359451133350283742854338177917816199855370966725059377660312824879861277400624102267119229693994595857701696025366109135127015217981691938713787569
peek = 6745414226866166172286907691060333580739794735754141517928503510445368134531623057
enc = 60939585660386801273264345336943282595466297131309357817378708003135300231065734017829038358019271553508356563122851120615655640023951268162873980957560729424913748657116293860815453225453706274388027182906741605930908510329721874004000783548599414462355143868922204060850666210978837231187722295496753756990
from Crypto.Util.number import long_to_bytes as ltb 


P.<x> = PolynomialRing(Zmod(n))
f = peek * 2 ^ 240 + x
ans = f.small_roots(X = 2^241, beta = 0.5, epsilon = 1/40)
p = peek * 2 ^ 240 + ans[0]
q = Integer(n) // Integer(p)
assert(p * q == n)
d = pow(65537, -1, (p-1)*(q-1))
print(ltb(int(pow(enc, d, n))))
```

Flag:
```HCMUS-CTF{d0nt_b3_4n_3XhiB1ti0ni5t_0r_y0uLL_g3t_eXp0s3d}```
### 3. M side
```python
from Crypto.Util.number import getStrongPrime, bytes_to_long as b2l, isPrime
import os


FLAG = os.getenv('FLAG', 'FLAG{hue_hue_hue}').encode()
p = getStrongPrime(512)
q = getStrongPrime(512)
while not isPrime(4 * p * p + q * q):
    p = getStrongPrime(512)
    q = getStrongPrime(512)

hint = 4 * p * p + q * q
e = 65537
print(f"hint: {hint}")
# n for wat?
print(f"ct: {pow(b2l(FLAG), e, p * q)}")

"""
hint: 461200758828450131454210143800752390120604788702850446626677508860195202567872951525840356360652411410325507978408159551511745286515952077623277648013847300682326320491554673107482337297490624180111664616997179295920679292302740410414234460216609334491960689077587284658443529175658488037725444342064697588997
ct: 8300471686897645926578017317669008715657023063758326776858584536715934138214945634323122846623068419230274473129224549308720801900902282047728570866212721492776095667521172972075671434379851908665193507551179353494082306227364627107561955072596424518466905164461036060360232934285662592773679335020824318918
"""
```

In this challenge, the only information we know about is a hint: ```4 * p^2 + q^2``` and it's prime, we have no clue about n. So how can we find it? This challenge actually only require some searching OSINT skill to solve (I even use chatgpt to do it). This prime is called : Gaussian prime (not really because gaussian prime have form like : a + b.i), and there is a [tool online](https://www.alpertron.com.ar/GAUSSIAN.HTM) that can find a and b( in our case: p and q). This consider to be the easiest challenge as no math are required to solve (I hope that using chatgpt is not considered violating the rules :P).

Flag:
```HCMUS-CTF{either_thu3_0r_3uclid_wh1ch3v3r_it_t4k35}```

### 4. Falsehood
```python
import os
import numpy as np
from sage.all import ComplexField, PolynomialRing
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random
from binascii import hexlify

FLAG = os.getenv('FLAG', "FLAG{this is a real flag}")
bits = 1111
C = ComplexField(bits)
P = PolynomialRing(C, names='x')
(x,) = P.gens()

key_array = np.random.choice(256, size=(16,))
key = b''.join([int(i).to_bytes(1, 'big') for i in key_array])

f = sum([coeff * x**i for i, coeff in enumerate(key_array)])
hint = []
for _ in range(16):
    X = random.randint(10**8, 10**10)
    Y = int(abs(f(X)))
    while [X, Y] in hint:
        X = random.randint(10**8, 10**10)
        Y = int(abs(f(X)))
    hint.append([X, Y])


cip = AES.new(key, AES.MODE_CBC)
ct = cip.encrypt(pad(FLAG.encode(),16))
iv = cip.iv
with open('output.txt', 'w') as file:
    file.write(str(hint)+'\n')
    print(f"ct = {hexlify(ct).decode()}, iv = {hexlify(iv).decode()}", file=file)
```
Things might be complicated at first glance, but I will simplify it so that you can understand it as well.
We have a polynomial ring in complexfield(in this challenge, it not really necessary as we only work with integers), variable x, and an polynomial f = coeff_0 * x^0 + coeff_1 * x^1 + coeff_2 * x^2 + ... + coeff_16 * x^15. We are also given 16 pairs of (x,y) is the parameter x and resulter f(x), you may notice that y = abs(f(x)) - which mean we dont know the sign of result, but this is also not necessary as we only work with positive integers (I am not sure if this is just like making things complicated?). So, base on information giving above, we can convert this into linear equations and solving it using matrix (You may notice that in my code, there is a part which I bruteforcing the sign, yearh I know I am stupid, but when I realize this, I am just too lazy to fix it, so ...)

Source:
```python
params = [[8833677163, 7159466859734884050485160017085648949938620549936739498951806707835448713685207536552299918328868591349533273061478374089984223260577742322460362334647], [1762352339, 226021067407224282748442153993506422184559341973942542463611713009302649608941949660293486972516731321467369225717344439888178648461773300463], [6814325828, 145915445591160853098610646953738314537732696913127480076359637783667652244881400087606152610739138506056218199806589240306741950875956525839170443027], [7865890147, 1255960511416167089973436987379886082394930531153251392262351559661203914293720867397614316726175343133363293139291718249474745356688772183204229822751], [3446680058, 5293859406843167459297872689128502546567761548640003856519557803475599388573073027426285178678302790672452768542207529392596772806973985884693237], [5877771652, 15883583178415793156782570756223737797760371065858523945056072346852806064052610100332389954372845836435762293469821829936427366159434784004504398291], [5589586633, 7472281200056449019563455444999813482028446397663996508394508567670602924631065370355170602075256758870709465268255309886778027432655593535614166637], [1175276268, 518629639886914674796931012497083502361229856009622285824810204881645367508380387007577326543311405957619591605841895258801496781885398507], [3312651249, 2920072124198357353277671402963439479294095254775553378538026906919501392975483266953780010186413153114694525677661955925502702904273824951901573], [1690420045, 120969905638890571692249167310237577968012605711450331530578304692989016303379573026678222839813088165787719888874515256743894818676147474521], [8298141391, 2802013920829536770649820952830225273137583982204944734413323800249577243089166668778583649665043009034143120874987986020037964205143133245123290632883], [733386150, 439287044309927586596972381366960178061704411347096135895831191742005839221734048948610767236121358802659929070752762370822244956535801], [7897145685, 1332938401210287323326359805632057169759318295533885927320250339098837407040892547133970478663396358868892779722453565866390506758764909670000617998161], [9797888335, 33864534898740204255025855638155912349784294672865719351405048784504660475905319925895086755774471151890089727930776090169445401259844048317273142069811], [4557234547, 349364318043137479854576449493426376983315472777226775365310579193760250715517761090058069937282741206013319707277840448237966901906357292702335951], [7667001731, 855344863189641492213600127143839128290386097202448105626863527763958015786114563445357087338205788545215994676722500375202243293047596358065835329663]]
ct = bytes.fromhex('be205fd34ebe59af55ea11fec9aea50197fbf35d5b52c650a6c9563186625e8b6021ba31db538fa4b60c69a42c96ee3bebaba53ac9afa9c3c185d4d0b145bc8251d892c243f1aa4037aeea003714e24c')
iv = bytes.fromhex('370abc6fce33f812de7b88daaa82e4c4')

def find_key(mask):
    ma = [[0 for i in range(16)] for j in range(16)]
    cnt = 0
    res_vector = []
    for x,y in params:
        for i in range(16):
            ma[cnt][i] = x ^ i
    
        if mask & 1:
            res_vector.append(-y)
        else:
            res_vector.append(y)
        mask >>= 1
        cnt += 1
    nvector = vector(res_vector)
    try:
        newma = Matrix(ma)
        ans = newma.solve_right(nvector)
    except:
        return False, []
    for i in ans:
        if round(i) != i:
            return False, []
    return True, ans

def decrypt_flag(key):
    newkey = b"".join(int(i).to_bytes(1, "big") for i in key)
    from Crypto.Cipher import AES 
    cipher = AES.new(newkey, AES.MODE_CBC, iv)
    return newkey, cipher.decrypt(ct)


for mask in range(0, (1<<16) - 1):
    F, key = find_key(mask)
    if F:
        nkey, flag = decrypt_flag(key)
        print(f"Possible flag found\nKey : {nkey.hex()}\nFlag: {flag.decode()}")
```
Flag:
```HCMUS-CTF{just_because_you're_correct_doesn't_mean_you're_right}```

### 5. Cry1
```python
import time
import random
import threading
import socketserver
import os

FLAG_FILE = os.getenv("FLAG")
PORT = int(os.getenv("APP_PORT"))
HOST = "0.0.0.0"

assert FLAG_FILE is not None, "Environment variable FLAG not set"
assert PORT is not None, "Environment variable APP_PORT not set"


class Service(socketserver.BaseRequestHandler):
    def handle(self):
        self.flag = self.get_flag()
        self.user_id = int(time.time())
        self.send(f"Welcome\n")
        assert len(self.flag) == 26
        self.send(
            f"Here is your encoded flag: {self.encode(self.flag, self.gen_key(self.user_id, len(self.flag)))}\n"
        )

    def get_flag(self):
        with open(FLAG_FILE, "r") as f:
            return f.readline()

    def encode(self, data, key):
        return sum([a * ord(b) for a, b in zip(key, data)])

    def gen_key(self, user_id, n):
        random.seed(user_id)
        return [random.randrange(1024) for i in range(n)]

    def send(self, string: str):
        self.request.sendall(string.encode("utf-8"))

    def receive(self):
        return self.request.recv(1024).strip().decode("utf-8")


class ThreadedService(
    socketserver.ThreadingMixIn,
    socketserver.TCPServer,
    socketserver.DatagramRequestHandler,
):
    pass


def main():
    service = Service
    server = ThreadedService((HOST, PORT), service)
    server.allow_reuse_address = True
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    print("Server started on " + str(server.server_address) + "!")
    # Now let the main thread just wait...
    while True:
        time.sleep(10)


if __name__ == "__main__":
    main()
```
What does this challenge do is it generate a random sequence using ```seed = int(time.time())``` and give us an encoded flag with ``` flag = sum([a * ord(b) for a, b in zip(key, data)])```. Ok, at this point, I think some of you guys already know how we actually gonna solve it: linear equation. Collecting 26 samples and building matrix for solving this (similar idea to the ```Falsehood``` challenge). The only problem here is that how can we get the correct samples. When I first trying to do it, some problem raise:
-   How do we getting the seed?
-   Even if we can get the seed, how can we dealing with the delaying (this because when connecting and sending data, there are some miliseconds delay the process, make it match with uncorrectly seed)

For the first problem, actually, time.time() on python is all equal(yes, It is a universal measure of time and is not affected by the time zone or location. The epoch is the point where the time starts, the return value of time.gmtime(0). It is January 1, 1970, 00:00:00 (UTC) on all platforms. ). So you don't have to worry about it, just time.time() right after the connection success and it is done.
For the second problem, how do we dealing that? If we connecting and getting sample, sometime you will see that there are some adjacent samples that have the same seed but the result is different. This is because there is delay between connection and sending data( very small, about 0.1 second and you may not notice it). So to make sure every seed is different, just sleep(1) and thing's done? Not yet, because of delying, some time the seed on server is ```seed = int(0.9) = 0``` but the delaying make the seed we get incorrectly ```seed = int(0.9 + delay) = int(0.9 + 0.1) = 1```.
So to fix this, I measure the time it take to complete get each sample and subtract it with time to sleep : ```sleep(1 - (begin - end))```. I also even force that queries are only send after the floating point of time.time() is greater than 0.3. One things about this, is that this challenge took me 2 hours to just only generating the correct sample(it's really sad bro).

Getting sameple:
```python
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
```
Yes, I am lazy to automate things you know.

Solution:
```python
import random 
def generate_list(seed):
    random.seed(seed)
    return [random.randrange(1024) for i in range(26)]

lmao = [(1683435939, 1219711), (1683435940, 1224123), (1683435941, 1194619), (1683435942, 1095408), (1683435943, 984803), (1683435944, 1141199), (1683435945, 1008197), (1683435946, 992136), (1683435947, 975927), (1683435948, 1152572), (1683435949, 1162287), (1683435950, 1044738), (1683435951, 1208867), (1683435952, 1261176), (1683435953, 980465), (1683435954, 960236), (1683435955, 1093138), (1683435956, 1128829), (1683435957, 1094842), (1683435958, 1193699), (1683435959, 1241068), (1683435960, 1193695), (1683435961, 1212768), (1683435962, 996452), (1683435963, 1114339), (1683435964, 1112003)]
ma = []
result = []
for seed, enc in lmao:
    ls = generate_list(seed)
    ma.append(ls)
    result.append(Integer(enc))

newma = Matrix(ZZ, ma)

ans = newma.solve_right(vector(result))

for i in ans:
    print(round(i), end = " ")
print(ans)
flag = "" 
for i in ans:
    if abs(i) > 128:
        continue
    else:
        flag += chr(abs(i))
print(flag)
```
Flag:
```HCMUS-CTF{the_EASIEST_0ne}``` (Easiest, but longest to solve)

### 6. Real key
Into the hardest problems:
```python
from Crypto.Cipher import AES
from Crypto.Util.number import getRandomInteger
from Crypto.Util.Padding import pad
import numpy as np




def gen_key():
    key = getRandomInteger(128).to_bytes(16, 'big')
    while b'\0' in key: key = getRandomInteger(128).to_bytes(16, 'big')
    mat = [[i for i in key[k:k+4]] for k in range(0, 16, 4)]
    return key, mat

def f(mat):
    """Make the key wavy"""
    N = 1600
    T = 1/800
    x = np.linspace(0, N*T, N)
    ys = [np.sum(np.array([.5**i * np.sin(n * 2 * np.pi * x) for i, n in enumerate(b)]), axis=0).tolist() for b in mat]
    return ys

def check_good_mat(mat):
    for row in mat:
        for i in range(4):
            if row[i] > 255: return False
            for j in range(i + 1, 4):
                if -1 == row[i] - row[j] or row[i] - row[j] == 1 or row[i] == row[j]: return False
    return True


                 
key, mat = gen_key()
while not check_good_mat(mat):
    key, mat = gen_key()

ys = f(mat)
FLAG = pad(b'FLAG{real_flag_goes_here}', 16)
cip = AES.new(key, AES.MODE_CBC)
iv = cip.iv

ciphertext = cip.encrypt(FLAG)

# The stuff which will be given
with open('output.txt', 'w') as ofile:
    print(ys, file=ofile)
with open('ciphertext.bin', 'wb') as ofile:
    ofile.write(iv)
    ofile.write(ciphertext)
```

I will assume that you have read and understand what is the problem in this challenge (lazy to explain again :P). There are 2 way to solve this:
-   Fourier transform
-   Bruteforcing, but smarter.

So why Fourier Transform? The f = sin(x.a_1.2.pi) + sin(x.a_2.2.pi) + ... + sin(x.a_n.2.pi) is a wave function combining from lots of sine function. And Fourier transform allow us to seperate f into individual sine function (yes, that is possible), thats sound cool, ha? The sad thing is, I don't know about FT( I just know about it recently). So I using a better thing: bruteforcing. It's not really like bruteforce, the thing I used is from ```scipy.optimize``` and its called ```differential_evolution```. Basically, we give and objective function to this, and some params with results, and what it does is finding an optimal answer that giving the different from expected result as small as it can. In my code:
```python
def objective_func(a, q):
    ys = ok(a)
    return np.sum((ys - q) ** 2)
```
The result in objective function is being squared, why? Because the closer result is, the better, optimizer answer we can find -> closed to the roots, or in our case: the key.

Solution:
```python
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
```
You might see that ook is set from the beginning, right? That is, some case, it will give the wrong answer( as closed as the roots, but that is not the answer). So to avoid it, I do some test by hand, and combining the answer to have the final result.

Flag:
```HCMUS-CTF{https://www.youtube.com/watch?v=nmgFG7PUHfo}```

# Pwnable
I solved 2 out of 4.
Because CTF has end, I cannot find the challenge files(also the server is closed too), so I will explain it by what I can remember.
In the first challenge, it just a normal BOF challenge, overflow the first char array to fill the second array and it's done.
In the second challenge - coin mining. 2 things need to do:
-   Find the canary
-   Find the libc base address
Here is the disassemble source code from binary:
![](https://github.com/sinkthemall/Cryptography_Writeup/blob/main/HCMUS_CTF/2023/coin_mining/coin_mining_source.png)
In the first problem, it's actually not hard as ```read(0, buf, 0x200uLL);``` allow us to read up to 0x200 characters, so just fill the buffer until it reach canary. The ```printf("%s??\n", buf);``` will print all character from buf until it reach null byte( because we already fill up with "a" bytes, so it also print out the canary), from here, we have the canary and can make ROP gadget.
In ther second problem