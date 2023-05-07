alphabet = 'abcdefghijklmnopqrstuvwxyz'.upper()
n = 26
sbox = [i for i in range(n)]
from random import shuffle
shuffle(sbox)
t_sbox = [0 for i in range(n)]
for i in range(n):
    t_sbox[sbox[i]] = i

msg = open('d:\\msg_enc.txt').read()
offset = 1
#caculate from last to first character, so we have to caculate last offset
def re_transform(msg, offset):
    pos = alphabet.index(msg)
    return t_sbox[(pos - offset)%n]
    
decrypted_msg = ''
for i in range(0,len(msg), 5):
    for j in range(5):
        if msg[i + j] == '_':
            decrypted_msg += msg[i + j]
        else:
            decrypted_msg += alphabet[re_transform(msg[i + j], offset)]
    offset = (offset*3 + 4)%n 
print(decrypted_msg)
