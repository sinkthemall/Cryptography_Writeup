from PIL import Image

def calculate_permutation(img_name, enc_name, x, y):
    img = Image.open(img_name)
    enc = Image.open(enc_name)
    d_img = img.load()
    d_enc = enc.load()
    trans = {}
    ans = {}
    for i in range(256):
        for j in range(256):
            if d_enc[i,j] != 0:
                trans[d_enc[i,j]] = (i,j)
    #print(len(trans))
    for i in range(x, x + 16):
        for j in range(y, y + 16):
            if d_img[i,j] != 0:
                ans[(i, j)] = trans[d_img[i,j]]
    
    return ans

original_flag = Image.new('RGB', (256,256), color = (255,255,255))
flag = original_flag.load()

for num in range(112, 143, 2):
    row = num // 16
    column = num%16 
    img_name = 'd:\\generate_image\\img_' + str(num) + '.png'
    ans_name = 'd:\\generate_image\\ans_' + str(num) + '.png'
    x = row * 16
    y = column * 16
    permu1 = calculate_permutation(img_name, ans_name, y, x)

    column += 1
    img_name = 'd:\\generate_image\\img_' + str(num + 1) + '.png'
    ans_name = 'd:\\generate_image\\ans_' + str(num + 1) + '.png'
    x = row * 16
    y = column * 16
    permu2 = calculate_permutation(img_name, ans_name, y, x)
    
    enc_flag = Image.open('d:\\generate_image\\flag_' + str(num) + '.png')
    #print(enc_flag.mode)
    enc = enc_flag.load()
    print(len(permu1))
    print(len(permu2))
    for k, v in permu1.items():
        x1, y1 = k
        x2, y2 = v 
        flag[x1,y1] = enc[x2,y2]
    
    for k, v in permu2.items():
        x1, y1 = k
        x2, y2 = v 
        flag[x1,y1] = enc[x2,y2]
    print('complete:', num)

flag_list = [(9, 6), (9,7), (10,5), (10, 6), (11, 4), (11, 5), (12, 3), (12, 4), (6, 8), (6, 9), (5, 9), (5, 10), (4, 10), (4, 11), (3, 11), (3, 12), (2, 12), (2, 13), (1,13), (1,14), (0, 15)]
for row, column in flag_list:
    num = row * 16 + column
    img_name = 'd:\\generate_image\\img_' + str(num) + '.png'
    ans_name = 'd:\\generate_image\\ans_' + str(num) + '.png'
    x = row * 16
    y = column * 16
    permu1 = calculate_permutation(img_name, ans_name, y, x)
    enc_flag = Image.open('d:\\generate_image\\flag_' + str(num) + '.png')
    #print(enc_flag.mode)
    enc = enc_flag.load()
    print(len(permu1))
    print(len(permu2))
    for k, v in permu1.items():
        x1, y1 = k
        x2, y2 = v 
        flag[x1,y1] = enc[x2,y2]
    print('complete:', num)

for i in range(256):
    for j in range(256):
        if i%16==0 and j%16==0:
            flag[i,j] = (0,0,0)

original_flag.save('d:\\flag_show.png')