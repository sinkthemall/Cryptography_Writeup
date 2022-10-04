from venv import create
from PIL import Image
from pyparsing import col
#generation task, should not be much pain :D

#remember to naming task properly, otherwise u wont know where it  belong to
def create_image(pathfile, x, y):
    img = Image.new('L', (256,256), color = 0)
    d_img = img.load()

    cnt =0 
    for i in range(x, x + 16):
        for j in range(y, y + 16):
            d_img[i,j] = cnt
            cnt += 1
    img.save(pathfile)
    return

for row in range(7, 9):
    for column in range(0,16):
        img_name = 'd:\\generate_image\\img_' + str(row*16 + column) + '.png'
        print('image name:', img_name)
        x = row * 16
        y = column*16
        create_image(img_name, y, x)
        print("Created successfully!!!")

flag_list = [(9, 6), (9,7), (10,5), (10, 6), (11, 4), (11, 5), (12, 3), (12, 4), (6, 8), (6, 9), (5, 9), (5, 10), (4, 10), (4, 11), (3, 11), (3, 12), (2, 12), (2, 13), (1,13), (1,14), (0, 15)]
for row, column in flag_list:
        img_name = 'd:\\generate_image\\img_' + str(row*16 + column) + '.png'
        print('image name:', img_name)
        x = row * 16
        y = column*16
        create_image(img_name, y, x)
        print("Created successfully!!!")

