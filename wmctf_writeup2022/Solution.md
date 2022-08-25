# WMCTF 2022 writeup - Cryptography
## 1. ECC
```
flag bits: 606
e = 0x10001
n = 61262574892917665379101848600282751252633178779864648655116434051615964747592676204833262666589440081296571836666022795166255640192795587508845265816642144669301520989571990670507103278098950563219296310830719975959589061794360407053224254135937766317251283933110936269282950512402428088733821277056712795259
c = 16002162436420434728223131316901476099110904029045408221515087977802746863468505266500673611412375885221860212238712311981079623398373906773247773552766200431323537510699147642358473715224124662007742017000810447999989426207919068340364725395075614636875116086496704959130761547095168937180751237132642548997
G = (3364552845709696244757995625685399274809023621531082895612949981433844727622567352338990765970534554565693355095508508160162961299445890209860508127449468 : 4874111773041360858453223185020051270111929505293131058858547656851279111764112235653823943997681930204977283843433850957234770591933663960666437259499093 : 1)
3G = (8240596254289477251157504980772167439041663401504657696787046343848644902166655624353107697436635678388969190302189718026343959470011854412337179727187240 : 4413479999185843948404442728411950785256136111461847698098967018173326770728464491960875264034301169184074110521039566669441716138955932362724194843596479 : 1)
```
We are given a file which contains somekind of encryptions like RSA and ECC.
My first idea is that p (factor of n) might be the modulus of EC, so if we can find the modulus base on 2 points on the curve (G and 3G), we can decrypt c and get the flag.  
The idea to get the p base on two points:
-   Let's call G and 3G are (x1,y1) and (x2,y2)
-   We know that EC equation is ``` y^2 = x^3 + ax + b ( mod p) ```, if we replace (x1,y1) and (x2,y2) into the equation, we will get 2 different equations ``` y1^2 = x1^3 + ax1 + b ``` and ``` y2^2 = x2^3 + ax2 + b ```, subtracting it and we get 
``` y2^2 - y1^2 = (x2^3 - x1^3) + a(x2 - x1) ```. At this point, we can find A and B (modulo n).
-   Define f = x - A(mod n), we can use the small_roots method in sagemath to find the value x by setting ``` beta = 0.5 ```( we already know A is one root of f, but we want to find the smaller root, which is the real A modulo p)
-   After finding A, we can find p by computing the GCD of (A(mod n) - A(mod p)) with n
-   Having p and a, we can compute q, d, b easily and restore the flag

But after recovering p,q,d and decrypt C, we notice that it has bit_length less than the original flag's bit_length ``` C's bitlength = 202, flag's bitlength = 606 ```. I guess A and B parameter are also parts of the flag (this one is similar to the threetresures - CorCTF problem), combining them will get the real flag
```
a: 3629864911627283784723617758993690217446918991113173559686999
p: 8308060309959524788634404677678479024666400240233812713350984932475838872076486898595574202532027412806488106365658717017155800093596205985127436125626827
q: 7373872192463191738033336697886150566044010386580579101665086651212656675570461681793837375772679015765588192207913025640568056955479671819537473774809617
b: 988958437986133278846018591274848194060347135958347118693976
a's bit_length: 202
b's bit_length: 200
c's bit_length: 201
b'$$U_c0u1d_s01v3_e11iptiCurv3_s0_34sily$$0f19d82199a0db0dee31fa12330307ea90aa'
```
source code:
```python 
n = 61262574892917665379101848600282751252633178779864648655116434051615964747592676204833262666589440081296571836666022795166255640192795587508845265816642144669301520989571990670507103278098950563219296310830719975959589061794360407053224254135937766317251283933110936269282950512402428088733821277056712795259
e = 65537
c = 16002162436420434728223131316901476099110904029045408221515087977802746863468505266500673611412375885221860212238712311981079623398373906773247773552766200431323537510699147642358473715224124662007742017000810447999989426207919068340364725395075614636875116086496704959130761547095168937180751237132642548997
gx = 3364552845709696244757995625685399274809023621531082895612949981433844727622567352338990765970534554565693355095508508160162961299445890209860508127449468
gy = 4874111773041360858453223185020051270111929505293131058858547656851279111764112235653823943997681930204977283843433850957234770591933663960666437259499093
g3x = 8240596254289477251157504980772167439041663401504657696787046343848644902166655624353107697436635678388969190302189718026343959470011854412337179727187240
g3y = 4413479999185843948404442728411950785256136111461847698098967018173326770728464491960875264034301169184074110521039566669441716138955932362724194843596479
A = (((g3y^2 - gy^2) - (g3x^3 - gx^3))%n *pow((g3x - gx), -1, n))%n # modulo n
b = (gy^2 - gx^3 - A*gx)%n
P.<x> = PolynomialRing(Zmod(n))
f = x - A
#print("A:", A)
a = 0
i = 0
while True:# i am not sure about the actual upper bound of a, so i just bruteforce it
    q = f.small_roots(beta = 0.5, X = 2^i)
    if len(q) != 0:
        #print(q)
        a = q[0]
        break
    i += 1

print("a:", a)
from math import gcd 
p = gcd(A - a, n)
assert(p != n and p!= 1)
print("p:", p)
q = n// p 
print("q:", q)
d = pow(e, -1, (p-1)*(q-1))
c = pow(c, d, n)
b = (gy^2 - gx^3 - a*gx)%p 
print("b:", b)
print("a's bit_length:", int(a).bit_length())
print("b's bit_length:", int(b).bit_length())
print("c's bit_length:", int(c).bit_length())
from Crypto.Util.number import long_to_bytes
flag = (int(a)<<int(404)) | (int(b)<<int(202)) | int(c) 
print(long_to_bytes(flag))
```
## 2. nanoDiamond
[Problem's source code](https://github.com/sinkthemall/Cryptography_Writeup/tree/main/wmctf_writeup2022/problem/nanoDiamond)  
Problem's summary:
-   In this problem we have to pass exactly 50 rounds.
-   Each round we have 6 chest, each chest contains either 0 or 1, our problem is to find total 6 chest's state.
-   We can find chests's state by asking question to the Skeleton Merchant, he will only anwer Yes or No. And we are able to ask him 14 question, but he might lie to us at most twice.
-   After 14 questions, we have to give the correct chests's state. If the answer wrong even 1 chest, we lose, but if we can pass to 50 rounds, we will be given the flag.  
After finishing this problem, I asked other members about how they pass it. And suprisingly, there are many ways to pass this( lots of it using luck to pass, i dont know how using luck can pass the rounds, maybe problem can not give the case where it fail, but i guess luck is one factor of skill (: ). But i will show you my way to pass it. My strategy is very complicate, so you want something more simple, you can search ``` Ulam's game ``` to know about the way to solve this.

### Strategy
-   Our first task is to ask the Merchant what is the value of chest_i, i will call this as the temporary state( we dont need to know which is fake or real). At this point, we use 6 question and have 8 questions left.
-   We dive 6 chest into 2 group. Group 1 contains chest 1, chest 2, chest 3. Group 2 contains chest 4, chest 5, chest 6.
-   Next, we use 2 question to ask Merchant. We ask the Merchant ``` if there is a fake chest in Group 1( fake chest means chest's answer is lie, from now, i will call a lie is a fake asnwer, fake chest, ...)```. The same question is ask to Group 2. There will be 3 cases total (at this part, we have 6 question left):
    -   Merchant's answer is ``` YES YES```:  
        This means Group 1 and Group 2, each group contains a fake answer( whether the ``` YES ``` is fake or real, we will know excatly that each group have 1 fake). So the rest 6 question is Real answer, we just ask the chests's value and it's done.  

    -   Merchant's answer is ``` NO NO ```:
        In this case, the fake answer can be ``` 0 2 ``` (0 2 in here means there isn't fake answer in this group1 or there are 2 fake asnwer) in each group . Because if the ``` NO ``` answer is fake, then that group have at least 1 fake answer ( thus 1 fake from ``` NO ``` + 1 fake from Group 1 = 2, we have used up 2 fake answer), and if the ``` NO ``` is real, it means that group have no fake answer, total fake asnwer we know will be = 0.  
        Our fake answer in each group right now are ``` 0 / 2 ``` or ``` 2 / 0 ``` or ``` 0 / 0 ```.
        Next we ask again the question ``` if there is a fake chest in Group 1 ``` (at this point we have 5 left).  
        There will be 2 case:  

        -   ``` NO ```: this answer can be fake, because if it's fake, then the previous answer is also fake, and there exist 1 fake answer in group 1, total is 1 + 1 + 1 = 3 (impossible). So the Group 1 is real.  
            To deal with this case, we use the following algorithm:  
            Let's assume the temporary state of each chest in Group 2 is ``` 0 0 0 ```. Ask each chest value again(at this point, 2 question remain). There will be 3 case:  
            -   ``` 0 1 0 ``` or any case containing only 1 different from temporary state, use 2 question to ask the chest 2(or the chest which have the different) value. The cases will be:  
                ``` 
                0 0 0
                0 1 0
                  1
                  1
                ```
                We chose 1 is the value of chest 2 as when 3 answer is the same, it cannot be fake  
                ```
                0 0 0    0 0 0
                0 1 0 or 0 1 0 (two 0 and two 1)
                  1        0
                  0        1
                ```
                We chose the 0 (the value we ask from beginner). Because if 0 is fake then the collumn 2 should be ``` 0 1 1 1 ```  
                ```
                0 0 0
                0 1 0 (three 0 and one 1)
                  0
                  0
                ```
                We chose 0, the value we ask from beginning.
            -   ``` 0 1 1 ``` or any case that cotaining 2 different from temporary state, the values ``` 0 0 0 ``` are the real value
            -   ``` 0 0 0 ```, same as case above  

        -   ``` YES ```: either this is real or fake, the Group 2 will be real( ``` NO ``` answer and the chests's state are real). Because if ``` YES ``` is real, we already use 2 fake answer in group1, if it's fake, then the other fake question can not be in group 2(fake answer in group 2 can only be 0 or 2). Again, ask another question ``` if there is a fake chest in Group 1 ``` (at this point, we have 4 left).  
            -   If ``` YES ```, the Group 1 is definitely contains 1 fake chest, and ``` NO ``` answer is fake, 4 question left, we use to ask the group1 state and it's done
            -   If ``` NO ```, Group 1 is real, we don't need to do anything.  

    -   Merchant's answer is ``` NO YES ```:  
    Definitely, ``` NO ``` is real, and that group is real too.(as NO answer giving that fake answer can only be 0 or 2, and the YES answer make sure that group have 1 fake answer, so we mst conclude NO is real). So, we only have at most 1 fake answer left. We use the following algorithm for the ``` YES ``` group:
    Again, let's the temporary state is ``` 0 0 0 ``` (I want to use temporary state as an example so you could make the algorithm for the other case). 
    We gonna ask each collumn (2 questions), then move to next collumn and do the same until we get the value 1(If you get 1, change to next collumn immediately to ask). If zero collumn(full collumn) or two 1 appear, stop immediately
    Example :
    ```
    0 0 0      0 0 0      0 0 0
    1 0    or  0 1    or  0
      1        1          0  
    ```
    NOTE : if you see a full collumn with zero, remove it from the matrix.
    Example:
    ```
    0 0 0                 0 0                            |     0 0 0              0 0
    0       will become       (remove the first collumn) | or  1 0   will become  1
    0                                                    |       0
    ```
    Cases will be:
    -   there are two 1 in matrix and remain questions is greater than or equal to the unknow chest: this case, remain questions are real, just ask the value
    -   ``` 
        0 0  (after asking) --->  0 0 (case 1)  or 0 0 (case 2)
        1                         1 0              1 1
        ```  
        This case , ask the second collumn, if we in case 2, 2 questions left are real, we just need to ask for value and it's done. If we in case 1, collumn 2 is real, we have to deal with collumn 1. Again, ask the group ``` if there is a fake chest in the group ``` two times. If one ``` YES ``` in two answer, collumn 2 is real, collumn 1 is fake, and its value is 1(collumn 1 : 1, collumn2 : 0). If both answers are ``` NO ``` , collumn 1 and 2 is real (collumn 1 : 0, collumn2 : 0)
    -   ```
        0 0
        0   
        1
        ```
        This case, ask the group ``` if there is a fake chest in the group ``` two times.  
        If ``` YES YES ```, collumn 1 is fake, collumn 2 is real( as two YES answer cannot be fake)  
        If ``` NO NO ```, collumn 1 and 2 is real (two NO answer cannot be fake)
        If ``` YES NO ``` or ``` NO YES ```, this is the hardest case, as we cannot figure out which is fake and real, so this case I let it randomly. But the chance to be in this case is very small ( about 8%). If you are not a fan of gaccha game, or just really bad luck, this definitely works very well.
About the source code, I won't paste it in here as the source is about 500 codelines. So if you want to know more about it, I will let the link [here](https://github.com/sinkthemall/Cryptography_Writeup/blob/main/wmctf_writeup2022/solve/nanoDiamond.py)
### 3.homo
This one, I didn't make it in tiem. You can find more explaination in https://imp.ress.me/blog/2022-08-22/wmctf-2022/ (my code idea is base on this)
```python
pk = eval(open("pubkey.txt").read())
ct = eval(open("cipher.txt").read())
def acd_attack(x, rho):
    R = 2^rho 
    B = [[0 for i in range(len(x))] for j in range(len(x))]
    B[0][0] = R 
    for i in range(1, len(x)):
        B[0][i] = x[i]
        B[i][i] = -x[0]
    B = Matrix(B)
    for i in B.LLL():
        if (i[0] != 0) and (i[0] %R == 0):
            return abs(i[0]//R)

q0 = acd_attack(pk[:7], 192)
print(q0)
from Crypto.Util.number import isPrime, long_to_bytes
sk_approx = (pk[0] // q0) - (2^191)//q0
print(sk_approx)
print(int(sk_approx).bit_length())
sk_approx += 1
flag = "".join(str((i%sk_approx)%2) for i in ct)
flag = int(flag, 2)
print(long_to_bytes(flag))



```
FLAG : 
```
17195743943555229331660961462727499
41565572874253689464437825525802665878958533473562648432875965578230785556539072257838190060392315994424904212374664222250474284551715262035741014468770452
514
b'sodayo>A<!!$%!$_Easy_G@CDp_ATtaCk'
```