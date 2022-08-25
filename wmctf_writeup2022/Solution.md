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
-   Let's call G and 3G are (x1,y1) and (x2,y2), we know that EC equation is ``` y^2 = x^3 + ax + b ```