# corCTF 2023 Cryptography writeup
Need explaination? DM me

# Fizzbuzz100
```python
#!/usr/local/bin/python
from Crypto.Util.number import *
from os import urandom

flag = open("flag.txt", "rb").read()
flag = bytes_to_long(urandom(16) + flag + urandom(16))

p = getPrime(512)
q = getPrime(512)
n = p * q
e = 0x10001
d = pow(e, -1, (p-1)*(q-1))
assert flag < n
ct = pow(flag, e, n)

print(f"{n = }")
print(f"{e = }")
print(f"{ct = }")

while True:
    ct = int(input("> "))
    pt = pow(ct, d, n)
    out = ""
    if pt == flag:
        exit(-1)
    if pt % 3 == 0:
        out += "Fizz"
    if pt % 5 == 0:
        out += "Buzz"
    if not out:
        out = pt
    print(out)
```

Script:
```python
from pwn import *
s = remote("be.ax", 31100)

s.recvuntil(b"n = ")
n = int(s.recvline(0).decode())
s.recvuntil(b"e = ")
e = int(s.recvline(0).decode())
s.recvuntil(b"ct = ")
ct = int(s.recvline(0).decode())

s.sendlineafter(b"> ", str((ct * pow(16, e, n))%n).encode())

out = int(s.recvline(0).decode())
from Crypto.Util.number import long_to_bytes as ltb
print(ltb((out * pow(16, -1, n))%n))
```

FLAG: ```corctf{h4ng_0n_th15_1s_3v3n_34s13r_th4n_4n_LSB_0r4cl3...4nyw4y_1snt_f1zzbuzz_s0_fun}```

### Eye

```python
from Crypto.Util.number import bytes_to_long, getPrime

# my NEW and IMPROVED secret sharing scheme!! (now with multivariate quadratics)

with open('flag.txt', 'rb') as f:
    flag = f.read()

s = bytes_to_long(flag)
p = getPrime(len(bin(s)))
print(p)
F = GF(p)
N = 1024

conv = lambda n: matrix(F, N, 1, [int(i) for i in list(bin(n)[2:][::-1].ljust(N, '0'))])

A = random_matrix(F, N, N)

for i in range(0, N):
    for j in range(0, i):
        A[i, j] = 0
B = random_matrix(F, N, 1)
C = matrix(F, [F(s)])

fn = lambda x: (x.T * A * x + B.T * x + C)[0][0]

L = []
for i in range(7):
    L.append(fn(conv(i + 1)))

print(L)
```
Script:
```python
from Crypto.Util.number import long_to_bytes as ltb


ok = [676465814304447223312460173335785175339355609820794166139539526721603814168727462048669021831468838980965201045011875121145342768742089543742283566458551844396184709048082643767027680757582782665648386615861, 1472349801957960100239689272370938102886275962984822725248081998254467608384820156734807260120564701715826694945455282899948399224421878450502219353392390325275413701941852603483746312758400819570786735148132, 202899433056324646894243296394578497549806047448163960638380135868871336000334692955799247243847240605199996942959637958157086977051654225700427599193002536157848015527462060033852150223217790081847181896018, 1065982806799890615990995824412253076607488063240855100580513221962298598002468338823225586171107539104635808108356492123167315175110515086192932230998426512947581115358738651206273178867911944034690138825583, 1676559204037482856674710667663849447914859348633288513196735253002541076530170853584406282605482862202276451646974549657672382936948091649764874334064431407644457518190694888175499630744741620199798070517691, 13296702617103868305327606065418801283865859601297413732594674163308176836719888973529318346255955107009306239107173490429718438658382402463122134690438425351000654335078321056270428073071958155536800755626, 1049859675181292817835885218912868452922769382959555558223657616187915018968273717037070599055754118224873924325840103339766227919051395742409319557746066672267640510787473574362058147262440814677327567134194]
p = 1873089703968291141600166892623234932796169766648225659075834963115683566265697596115468506218441065194050127470898727249982614285036691594726454694776985338487833409983284911305295748861807972501521427415609
ok1 = (ok[2] - (ok[1] + ok[0])) % p
ok2 = (ok[5] - (ok[1] + ok[3])) % p
ok3 = (ok[6] - (ok[4] + ok[1])) % p

flag = (ok3 - ok2 - ok1)% p
print(ltb(flag))
```

FLAG:```corctf{mind your ones and zeroes because zero squared is zero and one squared is one}```

### CBC
```python
import random

def random_alphastring(size):
    return "".join(random.choices(alphabet, k=size))

def add_key(key, block):
    ct_idxs = [(k_a + pt_a) % len(alphabet) for k_a, pt_a in zip([alphabet.index(k) for k in key], [alphabet.index(pt) for pt in block])]
    return "".join([alphabet[idx] for idx in ct_idxs])

def cbc(key, plaintext):
    klen = len(key)
    plaintext = pad(klen, plaintext)
    iv = random_alphastring(klen)
    blocks = [plaintext[i:i+klen] for i in range(0, len(plaintext), klen)]
    prev_block = iv
    ciphertext = ""
    for block in blocks:
        block = add_key(prev_block, block)
        prev_block = add_key(key, block)
        ciphertext += prev_block
    return iv, ciphertext
    
def pad(block_size, plaintext):
    plaintext += "X" * (-len(plaintext) % block_size)
    return plaintext

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
bs = 16

message = open("message.txt").read().upper()
message = "".join([char for char in message if char in alphabet])
flag = open("flag.txt").read()
flag = flag.lstrip("corctf{").rstrip("}")
message += flag
assert all([char in alphabet for char in message])

key = random_alphastring(bs)
iv, ct = cbc(key, pad(bs, message))
print(f"{iv = }")
print(f"{ct = }")
```
Some explaination: the scheme implemented in the challenge is cbc mod. There is nothing wrong with it except that it use shift cipher to encrypt a block, which can make this become vigenere cipher. There is a tool online can solve this with out key.

Script:
```python

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
def add_key(key, block):
    ct_idxs = [(k_a + pt_a) % len(alphabet) for k_a, pt_a in zip([alphabet.index(k) for k in key], [alphabet.index(pt) for pt in block])]
    return "".join([alphabet[idx] for idx in ct_idxs])

def sub_key(key, block):
    ct_idxs = [(pt_a - k_a) % len(alphabet) for k_a, pt_a in zip([alphabet.index(k) for k in key], [alphabet.index(pt) for pt in block])]
    return "".join([alphabet[idx] for idx in ct_idxs])

enc = "ZQTJIHLVWMPBYIFRQBUBUESOOVCJHXXLXDKPBQCUXWGJDHJPQTHXFQIQMBXNVOIPJBRHJQOMBMNJSYCRAHQBPBSMMJWJKTPRAUYZVZTHKTPUAPGAIJPMZZZDZYGDTKFLWAQTSKASXNDRRQQDJVBREUXFULWGNSIINOYULFXLDNMGWWVSCEIORQESVPFNMWZKPIYMYVFHTSRDJWQBTWHCURSBPUKKPWIGXERMPXCHSZKYMFLPIAHKTXOROOJHUCSGINWYEILFIZUSNRVRBHVCJPVPSEGUSYOAMXKSUKSWSOJTYYCMEHEUNPJAYXXJWESEWNSCXBPCCIZNGOVFRTGKYHVSZYFNRDOVPNWEDDJYITHJUBVMWDNNNZCLIPOSFLNDDWYXMYVCEOHZSNDUXPIBKUJIJEYOETXWOJNFQAHQOVTRRXDCGHSYNDYMYWVGKCCYOBDTZZEQQEFGSPJJIAAWVDXFGPJKQJCZMTPMFZDVRMEGMPUEMOUVGJXXBRFCCCRVTUXYTTORMSQBLZUEHLYRNJAAIVCRFSHLLPOANFKGRWBYVSOBLCTDAUDVMMHYSYCDZTBXTDARWRTAFTCVSDRVEENLHOHWBOPYLMSDVOZRLENWEKGAWWCNLOKMKFWWAZJJPFDSVUJFCODFYIMZNZTMAFJHNLNMRMLQRTJJXJCLMQZMOFOGFPXBUTOBXUCWMORVUIIXELTVIYBLPEKKOXYUBNQONZLPMGWMGRZXNNJBUWBEFNVXUIAEGYKQSLYSDTGWODRMDBHKCJVWBNJFTNHEWGOZFEZMTRBLHCMHIFLDLORMVMOOHGXJQIIYHZFMROGUUOMXBTFMKERCTYXFIHVNFWWIUFTGLCKPJRFDRWDXIKLJJLNTWNQIOFWSIUQXMFFVIIUCDEDFEJNLKLQBALRKEYWSHESUJJXSHYWNRNPXCFUEFRJKSIGXHFTKNJXSYVITDOGYIKGJIOOHUFILWYRBTCQPRPNOKFKROTFZNOCZXZEYUNWJZDPJDGIZLWBBDGZJNRQRPFFGOTGFBACCRKLAPFLOGVYFXVIIJMBBMXWJGLPOQQHMNBCINRGZRBVSMLKOAFGYRUDOPCCULRBE"
iv = "RLNZXWHLULXRLTNP"

encs = ""
prevblock = iv
for i in range(0, len(enc), 16):
    encs += sub_key(prevblock, enc[i : i + 16])
    prevblock = enc[i : i + 16]
print(encs)

# flag : corctf{ATLEASTITSNOTAGENERICROTTHIRTEENCHALLENGEIGUESS}
```
FLAG:```corctf{ATLEASTITSNOTAGENERICROTTHIRTEENCHALLENGEIGUESS}```
