import numpy as np
import sklearn.model_selection as train
from sklearn import tree
from sklearn.metrics import accuracy_score
import os

#数据目录
FilePath = os.path.abspath('..')+"\\data"


def loadData(filename,type):
    data = np.loadtxt(filename, dtype=type, delimiter=',',skiprows=2)
    x,y=np.split(data,indices_or_sections=(1,),axis=1)
    #后十个为属性值，第一个为标签
    x ,y= y[:,1:],x
    #前十个为属性值
    x_train,x_test,y_train,y_test=train.train_test_split(x,y,random_state=1,train_size=0.6)
    #随机划分训练集与测试集
    return x_train,x_test,y_train,y_test

def Train_Decision(x_train,y_train):
    clf = tree.DecisionTreeClassifier(max_depth=10)  # 创建DecisionTreeClassifier()类
    clf.fit(x_train, y_train.ravel())
    return clf

def Test_Decision(x_train,x_test,y_train,y_test,clf):
    if clf is None:
        raise IOError("Must input a clf!")
    y_hat = clf.predict(x_train)
    score = accuracy_score(y_hat, y_train)
    print('训练集准确率：{}'.format(score))
    y_hat=clf.predict(x_test)
    score=accuracy_score(y_hat,y_test)
    print('测试集准确率：{}'.format(score))

if __name__ == '__main__':
    print('加密前的数据：')
    x_train1, x_test1, y_train1, y_test1 = loadData(FilePath + '\\new_data.txt', float)
    clf1 = Train_Decision(x_train1, y_train1)
    Test_Decision(x_train1, x_test1, y_train1, y_test1, clf1)
    print('加密前第一组数据：')
    x_train11, x_test11, y_train11, y_test11 = loadData(FilePath + '\\new_data1.txt', float)
    clf11 = Train_Decision(x_train11, y_train11)
    Test_Decision(x_train11, x_test11, y_train11, y_test11, clf11)
    print('加密前第二组数据：')
    x_train12, x_test12, y_train12, y_test12 = loadData(FilePath + '\\data2.txt', float)
    clf12 = Train_Decision(x_train12, y_train12)
    Test_Decision(x_train12, x_test12, y_train12, y_test12, clf12)

    print('加密后的数据：')
    x_train2, x_test2, y_train2, y_test2 = loadData(FilePath + '\\new_processed.enc', int)
    clf2 = Train_Decision(x_train2, y_train2)
    Test_Decision(x_train2, x_test2, y_train2, y_test2, clf2)
    print('加密后第一组数据：')
    x_train21, x_test21, y_train21, y_test21 = loadData(FilePath + '\\new_processed1.enc', int)
    clf21 = Train_Decision(x_train21, y_train21)
    Test_Decision(x_train21, x_test21, y_train21, y_test21, clf21)
    print('加密后第二组数据：')
    x_train22, x_test22, y_train22, y_test22 = loadData(FilePath + '\\new_processed2.enc', int)
    clf22 = Train_Decision(x_train22, y_train22)
    Test_Decision(x_train22, x_test22, y_train22, y_test22, clf22)
