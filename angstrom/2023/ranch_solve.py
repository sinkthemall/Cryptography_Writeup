import string

# = open("flag.txt").read()



#shift = int(open("secret_shift.txt").read().strip())
def enc(encr, shift):
    encrypted = ""
    for i in encr:
        if i in string.ascii_lowercase:
            encrypted += chr(((ord(i) - 97 + shift) % 26)+97)
        else:
            encrypted += i


    print(encrypted)



encr = "rtkw{cf0bj_czbv_nv'cc_y4mv_kf_kip_re0kyvi_uivjj1ex_5vw89s3r44901831}"
for i in range(26):
    enc(encr, i)