import numpy as np
import math

from phe.encoding import EncodedNumber

import phe.paillier
# 生成Gram矩阵
from phe import paillier



def gram(list):
    len = np.shape(list)[0]
    Tlist = []
    gramMetric = []
    for i in list:
        Tlist.append(np.transpose(i))
    for i in range(len):
        for j in range(len):
            gramMetric.append(np.dot(list[i],Tlist[j]))
    return np.reshape(gramMetric,[len,len])


#加密
def EncryptedNumpy(public_key,array):
    array = gram(array)
    length=len(array)
    encrypted_line=[]
    encrypted_array=[]
    try:
        for i in range(0, length):
            for j in range(0, length):
                number = array[i][j]
                # 进行赋值操作，方便操作
                encrypted = public_key.encrypt(int(number))
                # 使用公钥加密
                encrypted_line.append(encrypted)
            encrypted_array.append(encrypted_line)
            encrypted_line=[]
        return encrypted_array
    except IOError:
        print('必须是矩阵')

#解密
def DecryptedNumpy(private_key,array):
    length = len(array)
    encrypted_line = []
    encrypted_array = []
    try:
        for i in range(0, length):
            for j in range(0, length):
                decrypted = private_key.decrypt_encoded(array[i][j], EncodedNumber)
                # 使用私钥解密
                encrypted_line.append(decrypted.decode())
            encrypted_array.append(encrypted_line)
            encrypted_line = []
        return encrypted_array
    except IOError:
        print('必须是矩阵')

def  add_product(a,b,public_key):
    alen = len(a)
    blen = len(b)
    addAB=[]
    ABline=[]
    if(alen<blen):
        a=lena2b(a,alen,blen,public_key)
    elif(alen>blen):
        b=lena2b(b,blen,alen,public_key)
    length=max(alen,blen)
    for i in range(0,length):
        for j in range(0,length):
            ABline.append(a[i][j]._add_encrypted(b[i][j]))
        addAB.append(ABline)
        ABline=[]
    return addAB


def lena2b(a,alen,blen,public_key):
    ilist = []
    new_a = []
    for i in range(0, blen):
        for j in range(0, blen):
            if i < alen:
                if j < alen:
                    ilist.append(a[i][j])
                else:
                    zero = public_key.encrypt(0)
                    ilist.append(zero)
            else:
                zero = public_key.encrypt(0)
                ilist.append(zero)
        new_a.append(ilist)
        ilist = []
    return new_a

if __name__=="__main__":
    # 数组数据
    array1 = [[12,2],[3,4],[7,8]]
    array2=[[5,3],[7,9]]
    public_key, private_key = paillier.generate_paillier_keypair()
    #生成公钥对
    encrypted1=EncryptedNumpy(public_key,array1)
    encrypted2=EncryptedNumpy(public_key,array2)
    encrypted=add_product(encrypted1,encrypted2,public_key)
    decrypted=DecryptedNumpy(private_key,encrypted)
    decrypted1=DecryptedNumpy(private_key,encrypted1)
    decrypted2=DecryptedNumpy(private_key,encrypted2)
    print(encrypted1)
    print(encrypted2)
    print(encrypted)
    print(decrypted)
    print(decrypted1)
    print(decrypted2)