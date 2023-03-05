pubkey = [7352, 2356, 7579, 19235, 1944, 14029, 1084]
privkey = ([184, 332, 713, 1255, 2688, 5243, 10448], 20910)
ciphertext = [8436, 22465, 30044, 22465, 51635, 10380, 11879, 50551, 35250, 51223, 14931, 25048, 7352, 50551, 37606, 39550]

def testkey(r):
    enc = ciphertext[ : ]
    q = privkey[1]
    arr = pubkey[ : ]
    for i in range(len(arr)):
        arr[i] = (arr[i] * pow(r, -1, q))%q
    
    if arr == privkey[0]:
        print("found r")
        print(r)

    flag = []
    for j in enc:
        s = j
        num = 0
        for i in range(6, -1, -1):
            if s >= arr[i]:
                s -= arr[i]
                num = num | (1 << (6 - i))
        flag.append(num)
    return bytes(flag)


from math import gcd

Q = privkey[1]
R = 0
for r in range(100, Q):
    arr = pubkey[ : ]
    if gcd(r, Q) == 1:
        for i in range(len(arr)):
            arr[i] = (arr[i] * pow(r, -1, Q)) %Q
        if arr == privkey[0]:
            print("found r")
        
            R = r 
            break

print("R =",R)
flag = []
enc = ciphertext[ : ]
arr = privkey[0]
for j in enc:
    c = (j * pow(R, -1, Q)) % Q 
    num = 0
    for i in range(6, -1, -1):
        if c >= arr[i]:
            num |= (1 << (6 - i))
            c -= arr[i]
            
    flag.append(num)
print(bytes(flag))
