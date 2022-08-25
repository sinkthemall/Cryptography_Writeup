
from pwn import *
from sympy import O, Q
s = remote("1.13.154.182", 31491)
round_num = 50
preround_num = 14
chest_num = 6
from string import ascii_letters, digits
from hashlib import sha256
from random import randint
eq = "=="
B = ["B0", "B1", "B2", "B3", "B4", "B5"]
tr = "1"
fa = "0"
def proof_of_work():
    msg = s.recvline().decode()[:-1]
    st, hsh = msg.split(" == ")
    st = st.replace("sha256(XXXX+", "")[:-1]
    print(st)
    print(hsh)
    q = ascii_letters + digits
    for i in q:
            for j in q:
                    for k in q:
                            for l in q:
                                    if sha256((i + j + k + l + st).encode()).digest().hex() == hsh:
                                        s.sendlineafter(b"Give me XXXX: ", (i + j + k + l).encode())
                                        return

    print("didnt found the hash")
    exit(0)
def flip(i):
    return f"( ( {i} == 0 ) and 1 )"
def exist(st):#not sure about this, payload about if exist fake element in set
    payload = " and ".join("( " + f"B{i}" + " == " + str(j) + " )" for i,j in st)
    payload = "( " + payload + " )"
    return flip(payload)

def yes_yes():
    K = [0 for i in range(6)]

    for i in range(6):
        payload = B[i] + " " + eq + " " + tr
        s.sendlineafter(b"Question: ", payload.encode())
        msg = s.recvline().decode()
        print(msg)
        if "Answer" in msg:
            if "True" in msg:
                K[i] = 1
            else:
                K[i] = 0
        else:
            print("Exception found!!!")
            exit(0)
    return K
def ask_value(i):
    payload = B[i] + " " + eq + " " + tr
    s.sendlineafter(b"Question: ", payload.encode())
    msg = s.recvline().decode()
    if "Answer" in msg:
        if "True" in msg:
            return 1
        else:
            return 0
    else:
        print("Exception found!!!")
        exit(0)
def nothing(k):#ask nothing k times
    print("this section just ask, nothing important")
    for i in range(k):
        payload = "1"
        s.sendlineafter(b"Question: ", payload.encode())
        msg = s.recvline().decode()
    print("end section")
def no_no(K1, K2):#in here, 6 questions remain
    K = [0 for i in range(6)]
    lt = []
    payload = exist(K1)
    #print(payload)
    s.sendlineafter(b"Question: ", payload.encode())
    msg = s.recvline().decode()
    print(msg)
    if "Answer" in msg:
        if "True" in msg:
            lt.append(1)
        else:
            lt.append(0)
        pass
    else:
        print("Exception found!!!")
        exit(0)
    if lt[0] == 0:
        #we have 5 question in this part
        Q = [0 for i in range(6)]
        pos, org = [], []
        for i , j in K2 :
            payload = B[i] + " " + eq + " " + tr
            s.sendlineafter(b"Question: ", payload.encode())
            msg = s.recvline().decode()
            #print(payload)
            #print(msg)
            if "Answer" in msg:
                if "True" in msg:
                    Q[i] = 1
                else:
                    Q[i] = 0
                if Q[i] != j:
                    pos.append(i)
                    org.append(j)
                pass
            else:
                print("Exception found!!!")
                exit(0)
        if len(pos) == 0:
            nothing(2)
        elif len(pos) == 1:
            pos = pos[-1]
            org = org[-1]
            print("pos:",pos, "org:",org)
            ch = 1
            for i in range(2):
                payload = B[pos] + " " + eq + " " + tr
                s.sendlineafter(b"Question: ", payload.encode())
                msg = s.recvline().decode()
                #print(msg)
                if "Answer" in msg:
                    if "True" in msg:
                        if 1==org:
                            ch += 1
                    else:
                        if 0 == org:
                            ch += 1
                    pass
                else:
                    print("Exception found!!!")
                    exit(0)
            
            if ch==3:
                Q[pos] = org
            elif ch == 2:
                Q[pos] = org
            else:
                Q[pos] = org^1
        else:
            for i in pos:
                Q[i] = ask_value(i)
        for i,j in K1:
            K[i] = j
        for i, j in K2:
            K[i] = Q[i]
        return K
    else:
        payload = exist(K1)
        #print(payload)
        s.sendlineafter(b"Question: ", payload.encode())
        msg = s.recvline().decode()
        #print(msg)
        if "Answer" in msg:
            if "True" in msg:
                lt.append(1)
            else:
                lt.append(0)
            pass
        else:
            print("Exception found!!!")
            exit(0)
    #at this part, 4 questions remain
    if lt[0] == 1 and lt[1] == 1:
        print("+ in case yes yes")
        for i, j in K1:
            payload = B[i] + " " + eq + " " + tr
            s.sendlineafter(b"Question: ", payload.encode())
            msg = s.recvline().decode()
            #print(msg)
            if "Answer" in msg:
                if "True" in msg:
                    K[i] = 1
                else:
                    K[i] = 0
            else:
                print("Exception found!!!")
                exit(0)
        nothing(1)
        for i, j in K2:
            K[i] = j
    elif (lt[0] == 0 and lt[1] == 1) or (lt[0] == 1 and lt[1] == 0):
        print("+ in case yes no or no yes")
        nothing(4)
        for i,j in K1:
            K[i] = j
        for i,j in K2:
            K[i] = j
    return K
def check_same(K):
    for i in range(len(K) - 1):
        if K[i] != K[i + 1]:
            return False
    return True

def no_yes(K1, K2): #6 question remain, assume K1 is no
    cnt = 0# this is for counting number of question used
    K = [0 for i in range(6)]
    for i , j in K1:
        K[i] = j
    Q = [[] for i in range(6)]
    for i, j in K2:
        Q[i].append(j)
    ch = 0
    complete =0 
    ask_list = []
    for i,j in K2:
        if complete >= 1:
            pass
        else:
            for k in range(2):
                cnt += 1
                payload = B[i] + " " + eq + " " + tr
                s.sendlineafter(b"Question: ", payload.encode())
                msg = s.recvline().decode()
                if "Answer" in msg:
                    if "True" in msg:
                        Q[i].append(1)
                    else:
                        Q[i].append(0)
                    if j != Q[i][-1]:
                        ch += 1
                        break
                else:
                    print("Exception found!!!")
                    exit(0)
        if len(Q[i]) != 3 or (not check_same(Q[i])):
            ask_list.append((i, j))
        elif len(Q[i]) == 3 and check_same(Q[i]):
            K[i] = j
            complete += 1
            print(f"completed Q[{i}]:",Q[i])
        if ch ==2 and (6-cnt) >=3:
            break
    if len(ask_list) == 0:
        print("+ ask list is empty")
        nothing(6 - cnt)
        pass
    elif len(ask_list) == 1:
        print("+ ask list len is 1")
        pass#no way this could happend, for sure
    elif (ch == 2) and (6 - cnt) >= 3:
        print("+ fake is gone")
        for i,j in K2:
            K[i] = ask_value(i)
            cnt += 1
        nothing(6 - cnt)
    elif (ch == 2) and (6 - cnt) >= len(ask_list):
        print("+ fake is gone too")
        for i,j in ask_list:
            K[i] = ask_value(i)
            cnt += 1
        nothing(6 - cnt)
    elif len(ask_list)==2:
        print("+ hardest case")
        i1, j1 =ask_list[0]
        i2, j2 =ask_list[1]
        while len(Q[i1]) < 3 and (Q[i1][-1] == j1):
            Q[i1].append(ask_value(i1))
            cnt += 1
        print(f"Q[{i1}]:", Q[i1])
        print(f"Q[{i2}]:", Q[i2])
        print(f"j1:",j1)
        print(f"j2:",j2)
        #done collumn 1(after remove full collumn)
        if Q[i1] == [j1, j1^1]:
            Q[i2].append(ask_value(i2))
            cnt += 1
            if Q[i2][-1] != j2:# that means all fake have been used
                for i,j in ask_list:
                    K[i] = ask_value(i)
                    cnt += 1
            else:
                ans= [ 0, 0]
                for i in range(2):#after this, all question haave been use
                    payload = exist(K2)
                    s.sendlineafter(b"Question: ", payload.encode())
                    msg = s.recvline().decode()
                    cnt += 1
                    #f*ck exception, i dont want to code it
                    if "True" in msg:
                        ans[i] = 1
                if ans[0] == 1 or ans[1] == 1:
                    K[i2] = j2
                    K[i1] = j1^1
                else:#NO NO, means NO real, and K2 is real, yes fake
                    for i,j in K2:
                        K[i] = j
        elif Q[i1] == [j1, j1, j1^1]:
            vl = ask_value(i1)
            cnt += 1
            if vl == (j1^1):
                K[i2] = j2
                K[i1] = ask_value(i1)
                cnt += 1
            else:
                K[i1] = j1
                K[i2] = ask_value(i2)
                cnt += 1
        else: #Q[i1] == [j1, j1, j1], means i1 real
            K[i1] = j1
            ans = [0, 0]
            for i in range(2):
                payload = exist(K2)
                s.sendlineafter(b"Question: ", payload.encode())
                msg=  s.recvline().decode()
                cnt += 1
                if "Answer" in msg:
                    if "True" in msg:
                        ans[i] = 1
                    else:
                        ans[i] = 0
                else:
                    print("Exception found!!!")
                    exit(0)
            #print("ans:",ans)
            if ans[0] == 1 and ans[1] == 1:
                K[i2] = j2^1
            elif ans[0] == 0 and ans[1] == 0:
                K[i2] = j2
            else:
                print("hardest hardest case")
                K[i2] = j2^1 #i dont know men, i wish i know, let the fate decide
        nothing(6-cnt)
    return K
    pass
def true_solve():
    K = [0 for i in range(6)]

    for i in range(6):
        payload = B[i] + " " + eq + " " + tr
        s.sendlineafter(b"Question: ", payload.encode())
        msg = s.recvline().decode()
        print(msg)
        if "Answer" in msg:
            if "True" in msg:
                K[i] = 1
            else:
                K[i] = 0
        else:
            print("Exception found!!!")
            exit(0)
    K1 = [(0, K[0]), (1, K[1]), (2, K[2])]
    K2 = [(3, K[3]), (4, K[4]), (5, K[5])]
    payload = exist(K1)#; print(payload)
    s.sendlineafter(b"Question: ", payload.encode())
    msg = s.recvline().decode()
    ans1 = 0
    ans2 = 0
    if "Answer" in msg:
        if "True" in msg:
            ans1 = 1
    else:
        print("Exception found!!!")
        exit(0)

    payload = exist(K2)#; print(payload)
    s.sendlineafter(b"Question: ", payload.encode())
    msg = s.recvline().decode()
    if "Answer" in msg:
        if "True" in msg:
            ans2 = 1
    else:
        print("Exception found!!!")
        exit(0)
    if ans1 and ans2:
        print("in case yes yes")
        K = yes_yes()
    elif (not ans1) and (not ans2):
        print("in case no no")
        K = no_no(K1, K2)
    else:
        print("in case no yes")
        if ans1 and (not ans2):
            K2, K1 = K1, K2
            #print("swapped")
        K = no_yes(K1, K2)
    payload = " ".join(str(i) for i in K)
    print("final answer:", payload)
    s.sendlineafter(b"Now open the chests:\n", payload.encode())

def solve_round():
    
    K1 = [0 for i in range(6)]
    K2 = [0 for i in range(6)]

    for i in range(6):
        payload = B[i] + " " + eq + " " + tr
        s.sendlineafter(b"Question: ", payload.encode())
        msg = s.recvline().decode()
        print(msg)
        if "Answer" in msg:
            if "True" in msg:
                K1[i] = 1
            else:
                K1[i] = 0
        else:
            print("Exception found!!!")
            exit(0)
        
    for i in range(6):
        payload = B[i] + " " + eq + " " + tr
        s.sendlineafter(b"Question: ", payload.encode())
        msg = s.recvline().decode()
        print(msg)
        if "Answer" in msg:
            if "True" in msg:
                K2[i] = 1
            else:
                K2[i] = 0
        else:
            print("Exception found!!!")
            exit(0)
    
    if K1 ==K2:#answer found
        for i in range(2):
            payload = B[i] + " " + eq + " " + tr
            s.sendlineafter(b"Question: ", payload.encode())
            msg = s.recvline().decode()
        s.recvuntil(b"Now open the chests:\n")
        payload = " ".join(str(i) for i in K1)
        #print(payload)
        s.sendline(payload)
    else:
        print(K1)
        print(K2)
        cnt = []
        for i in range(6):
            if K1[i] != K2[i]:
                cnt.append(i)
        if len(cnt) == 2:
            for i in cnt:
                payload = B[i] + " " + eq + " " + tr
                s.sendlineafter(b"Question: ", payload.encode())
                msg = s.recvline().decode()
                if "Answer" in msg:
                    if "True" in msg:
                        K2[i] = 1
                    else:
                        K2[i] = 0
                else:
                    print("Exception found!!!")
                    exit(0)
            s.recvuntil(b"Now open the chests:\n")
            payload = " ".join(str(i) for i in K2)
            #print(payload)
            s.sendline(payload.encode())
        else:
            ans = []
            cnt.append(cnt[-1])
            for i in cnt:
                payload = B[i] + " " + eq + " " + tr
                s.sendlineafter(b"Question: ", payload.encode())
                msg = s.recvline().decode()
                if "Answer" in msg:
                    if "True" in msg:
                        ans.append(1)
                    else:
                        ans.append(0)
                else:
                    print("Exception found!!!")
                    exit(0)
            if ans[0] == ans[1]:
                K2[cnt[-1]] = ans[0]
            s.recvuntil(b"Now open the chests:\n")
            payload = " ".join(str(i) for i in K2)
            print(payload)
            s.sendline(payload.encode())
proof_of_work()
print("done")
for i in range(round_num):
    print("round:",i)
    s.recvuntil(b"Skeleton Merchant can lie twice!\n")
    true_solve()
    msg = s.recvline().decode()
    if "A chest suddenly comes alive and BITE YOUR HEAD OFF." in msg:
        print("cannot pass round", i)
        break
    else:
        print("pass round", i)
s.interactive()