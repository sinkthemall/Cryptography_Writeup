from pwn import *
from base64 import b64encode, b64decode
from Crypto.Util.number import inverse, bytes_to_long, long_to_bytes
from hashlib import sha256
s = remote('103.245.250.31', 31850)
#time to caculate x
def option_select(a : str, s : remote):
    print(s.recvuntil(b'Select an option: ').decode())
    s.sendline(a.encode())

R,S = 0, 0
G,P = 0,0
def get_publicKey(s : remote):
    global G,P
    option_select('0', s)
    G = int(s.recvline().decode()[3:-1])
    P = int(s.recvline().decode()[3:-1])
    print('G =',G)
    print('P =',P)

def get_x(s : remote):
    global G,P
    global R,S
    option_select('1', s)
    print(s.recvuntil(b'Input message you want to sign: ').decode())
    payload = b64encode(b'\x00'*32)
    s.sendline(payload)
    print(s.recvuntil(b'Signature (r, s):  ').decode())
    R,S = eval(s.recvline()[:-1].decode())
    print((R,S))
    if R == G:
        print('correct path')

    #this is the part where i caculate x using Magic
    h = bytes_to_long(sha256(payload).digest())
    try:
        XR = (h - S)%(P-1)
        X =( XR*inverse(R, P-1))%(P-1)
    except:
        print('error')
        exit(0)
    return int(X)

def sign_message(s : remote):
    global R,S
    global G,P
    x = get_x(s)
    print('x = ',x)
    option_select('3', s)
    
    print(s.recvuntil(b'Could you sign this for me:  ').decode())
    msg_chall = s.recvline()[:-1]
    print(msg_chall)
    print(b64decode(msg_chall))
    h = bytes_to_long(sha256(msg_chall).digest())
    r = pow(G, 1, P)

    chall_S =( (h - x*r)*inverse(1, P-1))%(P-1)
    s.sendlineafter(b'Input r: ', b64encode(long_to_bytes(R)))
    s.sendlineafter(b'Input s: ', b64encode(long_to_bytes(chall_S)))
    print(s.recvline().decode())

get_publicKey(s)
sign_message(s)

