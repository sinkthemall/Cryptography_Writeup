from gettext import find


enc = bytes.fromhex('cb57ba706aae5f275d6d8941b7c7706fe261b7c74d3384390b691c3d982941ac4931c6a4394a1a7b7a336bc3662fd0edab3ff8b31b96d112a026f93fff07e61b')
las = ord('}')
dec = '}'
def find_b1(state):
    for b1 in range(128):
        if ((b1 ^ ((b1 << 1) | (b1 & 1))) & 0xff) == state:
            return b1
    return -1

def find_b2(state):
    for b2 in range(128):
        if ((b2 ^ ((b2 >> 5) | (b2 << 3))) & 0xff) == state:
            return b2

for b in enc[:-1][::-1]:
    b2 = (las ^ ((las >> 5) | (las << 3))) & 0xff
    b1 = (b - b2)%256
    las = find_b1(b1)
    dec += chr(las)
print(dec[::-1])