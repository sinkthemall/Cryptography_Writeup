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