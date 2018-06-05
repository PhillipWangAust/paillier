from sklearn import svm as svm
import numpy as np
import sklearn.model_selection as train
#处理旧数据
from sklearn.metrics import accuracy_score




'''
#数据处理
from phe import paillier
def process_data():
    ''''''
    处理旧数据
    :return: 新的数据集存放在data.txt中，未处理的数据存放在old_data.txt中
    ''''''
    file=open('old_data.txt','r')
    outfile=open('data.txt','w')
    lines=file.readlines()
    for line in lines:
        line = line.split(',')
        line[0],line[1]=line[1],line[0]
        if line[0]=='M':
            line[0]='1'
        else:
            line[0]='0'
        str=''
        for each in line:
            each='{},'.format(each)
            str=str+each
        str=str[:-1]
        outfile.write(str)

def Encrypt_data():
#加密数据，存到encrypted_data.txt
    public_key, private_key = paillier.generate_paillier_keypair()
    file = open('data.txt','r')
    outfile = open('encrypted_data.txt','w')
    msg='public key:{}\nprivate key:{}\n'.format(public_key,private_key)
    outfile.write(msg)
    lines=file.readlines()
    for line in lines:
        outline = []
        line = line.split(',')
        outline.append(line[0])
        for each in line[1:]:
            new=public_key.encrypt(float(each))
            outline.append(new)
        str='{},'.format(outline[0])
        for every in outline[1:]:
            every='{}'.format(every)
            str=str+every[-11:-2]+','
        str=str[:-1]+'\n'
        outfile.write(str)
        
def Hex2Dec():
#把加密后的16进制转10进制处理，存到process_data.txt中
    file = open('encrypted_data.txt', 'r')
    outfile = open('process_data.txt','w')
    lines = file.readlines()
    for line in lines[2:]:
        outline = []
        line = line.split(',')
        for each in line:
            new = (int(each,16))
            outline.append(new)
        str = '{},'.format(outline[0])
        for every in outline[1:]:
            every = '{}'.format(every)
            str = str + every[-11:-2] + ','
        str = str[:-1] + '\n'
        outfile.write(str)


def Classification(filename,outfilename1,outfilename2):
#分属性存储
    file = open(filename,'r')
    outfile1 = open(outfilename1,'w')
    outfile2 = open(outfilename2,'w')
    lines=file.readlines()
    for line in lines:
        out1 = []
        out2 = []
        line=line.split(',')
        out1.append(line[0])
        out1.append(line[1])
        out2.append(line[0])
        out2.append(line[1])
        length=len(line)
        for i in range(2,length):
            if i<17:
                out1.append(line[i])
            elif i==31:
                out2.append(line[i][:-1])
            else:
                out2.append(line[i])
        str1 = ''
        for each1 in out1:
            each1 = '{},'.format(each1)
            str1 = str1 + each1
        str2 = ''
        for each2 in out1:
            each2 = '{},'.format(each2)
            str2 = str2 + each2
        str1=str1[:-1]+'\n'
        str2=str2[:-1]+'\n'
        outfile1.write(str1)
        outfile2.write(str2)
'''

def loadData(filename,type):
    data = np.loadtxt(filename, dtype=type, delimiter=',',skiprows=2)
    x,y=np.split(data,indices_or_sections=(1,),axis=1)
    #后十个为属性值，第一个为标签
    x ,y= y[:,1:],x
    #前十个为属性值
    x_train,x_test,y_train,y_test=train.train_test_split(x,y,random_state=1,train_size=0.6)
    #随机划分训练集与测试集
    return x_train,x_test,y_train,y_test



def train_SVM(x_train,y_train):
    '''
    kernel='linear'时，为线性核，C越大分类效果越好，但有可能会过拟合（defaul C=1）。
　　 kernel='rbf'时（default），为高斯核，gamma值越小，分类界面越连续；gamma值越大，分类界面越“散”，分类效果越好，但有可能会过拟合。
　　decision_function_shape='ovr'时，为one v rest，即一个类别与其他类别进行划分，
　　decision_function_shape='ovo'时，为one v one，即将类别两两之间进行划分，用二分类的方法模拟多分类的结果。
    :param x_train: 数据集
    :param y_train: 分类标签
    :return:
    '''
    clf= svm.SVC(C=0.5,kernel='rbf',gamma=100,decision_function_shape='ovo')
    clf.fit(x_train,y_train.ravel())
    return clf

def test_SVM(x_train,x_test,y_train,y_test,clf=None):
    if clf is None:
        raise IOError("Must input a clf!")
    y_hat = clf.predict(x_train)
    score = accuracy_score(y_hat, y_train)
    print('训练集准确率：{}'.format(score))
    y_hat=clf.predict(x_test)
    score=accuracy_score(y_hat,y_test)
    print('测试集准确率：{}'.format(score))

print('加密前的数据：')
x_train1, x_test1, y_train1, y_test1=loadData('data.txt',float)
clf1=train_SVM(x_train1, y_train1)
test_SVM(x_train1, x_test1, y_train1, y_test1, clf1)
print('加密前第一组数据：')
x_train11, x_test11, y_train11, y_test11=loadData('data1.txt',float)
clf11=train_SVM(x_train11, y_train11)
test_SVM(x_train11, x_test11, y_train11, y_test11, clf11)
print('加密前第二组数据：')
x_train12, x_test12, y_train12, y_test12=loadData('data2.txt',float)
clf12=train_SVM(x_train12, y_train12)
test_SVM(x_train12, x_test12, y_train12, y_test12, clf12)

print('加密后的数据：')
x_train2, x_test2, y_train2, y_test2=loadData('process_data.txt',int)
clf2=train_SVM(x_train2, y_train2)
test_SVM(x_train2, x_test2, y_train2, y_test2, clf2)
print('加密后第一组数据：')
x_train21, x_test21, y_train21, y_test21=loadData('process_data1.txt',int)
clf21=train_SVM(x_train21, y_train21)
test_SVM(x_train21, x_test21, y_train21, y_test21, clf21)
print('加密后第二组数据：')
x_train22, x_test22, y_train22, y_test22=loadData('process_data2.txt',int)
clf22=train_SVM(x_train22, y_train22)
test_SVM(x_train22, x_test22, y_train22, y_test22, clf22)

