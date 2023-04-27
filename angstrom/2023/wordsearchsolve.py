enc = "(kh)k'k(Qj)Q'Q(2U)2'2(35)3'3(Ff)F(ul)u?hbjU5?'F(9M)9'9(4 C)4'4(iv)i?ofM?'u?tCl?(SP)S'S'i?Pvh?_(k4)k'k(Q0)Q'Q(2Y)2'2(9 j)9'9(uB)u(S I)S(N7)N(oH)o?40Yi?(3a)3'3(Fi)F'F'S(XG)X'o?arij?(4k)4'4'u(fs)f(d f)d?kBr?(ix)i'i'X(cH)c'd(VZ)V(q x)q'q(DJ)D(W B)W?eIxG?(sp)s's(xN)x'x(pD)p'p'N'W?pND7g?(Mq)M'M?uqH?'c'f'V?HsfZl?'D(eT)e'e(j N)j'j?xJaT??BNr?_(kh)k'k(QS)Q'Q(2U)2'2(32)3'3(FZ)F(4s)4(XG)X?hSaU2?'F(97)9'9'4(Sw)S'S?nZ7s?(uc)u'u(iQ)i'i'X?cdwQG?_(k6)k'k(Qq)Q'Q(F8)F(9 8)9(i v)i(e4)e?i6q?(2t)2'2(3i)3'3'F'9(4 u)4'4(p R)p(oK)o(f b)f(Vr)V(D8)D?tin8?(us)u'u(SF)S'i(X 1)X'X(sS)s(NR)N(c 9)c(q o)q?8eus?'S'p(M X)M'f(W f)W(jm)j?Fvx1?'s(xo)x'x'c?Sop?'M'e'j?rR?'N(d8)d?eRX?'o?sK9?'d'q'W?sb8?'V?iro?'D?8v4??efm?"
enc = "(kh)k'k(Qj)Q'Q(2U)2'2(35)3'3(Ff)F(ul)u?hbjU5?'F(9M)9'9(4 C)4'4(iv)i?ofM?'u?tCl?(SP)S'S'i?Pvh?_(k4)k'k(Q0)Q'Q(2Y)2'2(9 j)9'9(uB)u(S I)S(N7)N(oH)o?40Yi?(3a)3'3(Fi)F'F'S(XG)X'o?arij?(4k)4'4'u(fs)f(d f)d?kBr?(ix)i'i'X(cH)c'd(VZ)V(q x)q'q(DJ)D(W B)W?eIxG?(sp)s's(xN)x'x(pD)p'p'N'W?pND7g?(Mq)M'M?uqH?'c'f'V?HsfZl?'D(eT)e'e(j N)j'j?xJaT??BNr?_(kh)k'k(QS)Q'Q(2U)2'2(32)3'3(FZ)F(4s)4(XG)X?hSaU2?'F(97)9'9'4(Sw)S'S?nZ7s?(uc)u'u(iQ)i'i'X?cdwQG?_(k6)k'k(Qq)Q'Q(F8)F(9 8)9(i v)i(e4)e?i6q?(2t)2'2(3i)3'3'F'9(4 u)4'4(p R)p(oK)o(f b)f(Vr)V(D8)D?tin8?(us)u'u(SF)S'i(X 1)X'X(sS)s(NR)N(c 9)c(q o)q?8eus?'S'p(M X)M'f(W f)W(jm)j?Fvx1?'s(xo)x'x'c?Sop?'M'e'j?rR?'N(d8)d?eRX?'o?sK9?'d'q'W?sb8?'V?iro?'D?8v4??efm?"
flag = ""
if '[' in enc or ']' in enc:
    print("[] found")
if '*' in enc:
    print("* found")
if "." in enc:
    print(". found")
flag = []
temp = ['\x00' for i in range(128)]

def extract_key():
    i = 0
    lmao1 = []
    lmao2 = []
    while i < len(enc):

        if enc[i] == "(":
            tag = enc[i + 1]
            first = i + 2
            while enc[i] != ")":
                i += 1
            if i - first == 1:
                temp[ord(tag)] = enc[first]
            else:
                temp[ord(tag)] = enc[i-1]
                pass
        elif enc[i] == "'":
            tag = enc[i + 1]
            i += 1
            lmao2.append(temp[ord(tag)])

            pass
        elif enc[i] == " ":
            pass

        elif enc[i] == "?":
            i += 1
            while enc[i] != "?":
                lmao1.append(enc[i])
                i += 1
            for j in lmao1:
                if not (j in lmao2) and (j not in "0123456789"):
                    flag.append(j)
                    lmao2 = []
                    lmao1 = []
                    break
       #     flag.append()
        elif enc[i] == "_":
            flag.append("_")
            pass
        i += 1

        


suspicious = "(Ff)F(ul)u?hbjU5?'F"
debug_this_shit= "(ul)u?hbjU5?"
extract_key()
print("".join(flag))