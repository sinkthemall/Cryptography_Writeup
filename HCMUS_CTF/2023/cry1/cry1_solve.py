def find_flag(ls, total):
    ma = [[0 for i in range(27)] for j in range(27)]
    for i, j in enumerate(ls):
        ma[0][i] = j
    ma[0][26] = -total
    for i in range(1, 27):
        ma[i][i] = 1
    newma = Matrix(ma)
    newma = newma.transpose().LLL()
    flag = []
    print(newma)
    for row in newma:
        lmao = ''
        if row[0] == 0:
            notok = False
            for j in row[1:]:
                if abs(j) > 128:
                    notok = True
                    break
            if not notok:
                for j in row[1:]:
                    lmao += chr(abs(j))
        if lmao != '':
            flag.append(lmao)
    
    return flag
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

finalans = [ord(i) for i in "abcdefghijklmnopqrstuvwxyz"]
ok = []
for seed, enc in lmao :
    ok.append(sum(a * b for a, b in zip(generate_list(seed), finalans)))

# print(ok)
# print(result)
# assert(list(ok) == result)
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

