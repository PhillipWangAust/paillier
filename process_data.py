from phe import paillier

#处理数据的各种辅助函数
#数据来源：https://goo.gl/U2Uwz2
#数据处理
def process_data():
    '''
    处理旧数据
    :return: 新的数据集存放在data.txt中，未处理的数据存放在old_data.txt中
    '''
    file = open('old_data.txt', 'r')
    outfile = open('data.txt', 'w')
    lines = file.readlines()
    for line in lines:
        line = line.split(',')
        line[0], line[1] = line[1], line[0]
        if line[0] == 'M':
            line[0] = '1'
        else:
            line[0] = '0'
        str = ''
        for each in line:
            each = '{},'.format(each)
            str = str + each
        str = str[:-1]
        outfile.write(str)


def Encrypt_data():
    # 加密数据，存到encrypted_data.txt
    public_key, private_key = paillier.generate_paillier_keypair()
    file = open('data.txt', 'r')
    outfile = open('encrypted_data.txt', 'w')
    msg = 'public key:{}\nprivate key:{}\n'.format(public_key, private_key)
    outfile.write(msg)
    lines = file.readlines()
    for line in lines:
        outline = []
        line = line.split(',')
        outline.append(line[0])
        for each in line[1:]:
            new = public_key.encrypt(float(each))
            outline.append(new)
        str = '{},'.format(outline[0])
        for every in outline[1:]:
            every = '{}'.format(every)
            str = str + every[-11:-2] + ','
        str = str[:-1] + '\n'
        outfile.write(str)


def Classification(filename, outfilename1, outfilename2):
    # 分属性存储
    file = open(filename, 'r')
    outfile1 = open(outfilename1, 'w')
    outfile2 = open(outfilename2, 'w')
    lines = file.readlines()
    for line in lines:
        out1 = []
        out2 = []
        line = line.split(',')
        out1.append(line[0])
        out1.append(line[1])
        out2.append(line[0])
        out2.append(line[1])
        length = len(line)
        for i in range(2, length):
            if i < 17:
                out1.append(line[i])
            elif i == 31:
                out2.append(line[i][:-1])
            else:
                out2.append(line[i])
        str1 = ''
        for each1 in out1:
            each1 = '{},'.format(each1)
            str1 = str1 + each1
        str2 = ''
        for each2 in out2:
            each2 = '{},'.format(each2)
            str2 = str2 + each2
        str1 = str1[:-1] + '\n'
        str2 = str2[:-1] + '\n'
        outfile1.write(str1)
        outfile2.write(str2)


def Hex2Dec():
    # 把加密后的16进制转10进制处理，存到process_data.txt中
    file = open('new_encrypted.txt', 'r')
    outfile = open('new_processed.txt', 'w')
    lines = file.readlines()
    for line in lines:
        outline = []
        line = line.split(',')
        for each in line:
            new = (int(each, 16))
            outline.append(new)
        str = '{},'.format(outline[0])
        for every in outline[1:]:
            every = '{}'.format(every)
            str = str + every[-11:-2] + ','
        str = str[:-1] + '\n'
        outfile.write(str)


# 筛选infilename中的数据，保存到outfilenmae中，GoodData存放不需要的属性列，例如[1,2,3]
def GetGoodData(infilename='data.txt', outfilename=None, GoodData=None):
    file = open(infilename, 'r')
    outfile = open(outfilename, 'w')
    lines = file.readlines()
    for line in lines[2:]:
        line = line.split(',')
        newline = []
        for i in range(0, len(line)):
            if i not in GoodData:
                newline.append(line[i])
        str = ''
        for each in newline:
            each = '{},'.format(each)
            str = str + each
        str = str[:-1]
        outfile.write(str)