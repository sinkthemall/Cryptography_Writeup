from pwn import remote, log, args
import struct
import hashlib
from Crypto.Cipher import AES

n = 256
q = 11777
w = 8
HOST = '116.203.41.47' if args.REMOTE else '0.0.0.0'
PORT = 4421
io = remote(HOST, PORT)

################################################################


def center(v): return min(v % q, v % q-q, key=abs)


def extract(r, d): return [2*t//q for u, t in zip(r, d) if u]


def ppoly(g): return struct.pack(f'<{n}H', *g).hex()
def pbits(g): return ''.join(str(int(v)) for v in g)
def hbits(g): return hashlib.sha256(pbits(g).encode()).digest()
def mkaes(bits): return AES.new(hbits(bits), AES.MODE_CTR, nonce=b'')


def unpoly(g: bytes): return list(struct.unpack(f'<{n}H', g))
def unbits(g: str): return list(map('01'.index, g))


def get_param():
    a = io.recvline(0).decode().split(': ')[-1]
    a = unpoly(bytes.fromhex(a))
    b = io.recvline(0).decode().split(': ')[-1]
    b = unpoly(bytes.fromhex(b))
    c = io.recvline(0).decode().split(': ')[-1]
    c = unpoly(bytes.fromhex(c))
    r = io.recvline(0).decode().split(': ')[-1]
    r = unbits(r)
    flag = bytes.fromhex(io.recvline(0).decode().split(': ')[-1])
    return a, b, c, r, flag


def request_server(ct):
    c, r = ct
    io.sendline(ppoly(c).encode())
    io.sendline(pbits(r).encode())
    return io.recvline(0)


def query(ct, idx1, idx2):
    c, r = ct
    _r = r[:]
    _r[idx1] = 0
    res1 = request_server((c, _r))
    _r = r[:]
    _r[idx2] = 0
    res2 = request_server((c, _r))

    return 1 if res1 == res2 else 0


def main():
    log.setLevel('debug')
    a, b, c, r, enc_flag = get_param()
    bits = [1]
    idx1 = r.index(1)
    with log.progress("Brutefocing bits") as LMAO:
        for idx2 in range(idx1+1, len(r)):
            if not r[idx2]:
                continue
            check = query((c, r), idx1, idx2)
            if check:
                bits.append(bits[-1])
            else:
                bits.append(int(not bits[-1]))
            LMAO.status(f"{len(bits)}/256 - {bits}")
            idx1 = idx2
        LMAO.success(str(bits))
    log.success(str(mkaes([0] + bits).decrypt(enc_flag)))
    for i in range(len(bits)):
        bits[i] = int(not bits[i])
    log.success(str(mkaes([0] + bits).decrypt(enc_flag)))



main()
io.close()
