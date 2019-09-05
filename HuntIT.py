import pandas as pd
import re
import matplotlib.pyplot as plt

""" Preparation of datatset containing labelled data as normal and malicious traffic from raw logs (Ex:- Web server logs)"""

dframe = pd.DataFrame()
requesttype = []
responsecode = []
bytes1=[]
referer=[]
url=[]
useragent = []
nature = []


def anomalous(filename):
  f = open(filename,'r')
    doc = f.read()
    line = doc.split("\n")
    
    for l in line:
        if l[:4].__contains__("GET") or l[:4].__contains__("POST") or l[:4].__contains__("PUT") :
            url.append(l.split(" ")[1])
            nature.append("Malicious") 
        if l[:10].__contains__("User-Agent"):
            useragent.append(l.split(": ")[1])
     
             

def normal(filename): 
    f = open(filename,'r')
    doc = f.read()
    r1 = re.findall(r"(GET|POST|OPTIONS|TRACE|PUT|DELETE)\s(.*?)\s.*?(\d{3})\s(\d+)\s\"(.*?)\"\s\"(.*?)\"", doc)
    
    for x in r1:
        requesttype.append(x[0])
        url.append(x[1])
        responsecode.append(x[2])
        bytes1.append(x[3])
        referer.append(x[4])
        useragent.append(x[5])
        nature.append("Non-Malicious")  
  
     
anomalous("D:\\anomalous_Traffic.txt")
normal("D:\\normal_Traffic.txt")

dframe['URL'] = url
dframe["USERAGENT"] = useragent
dframe["REQUESTTYPE"] = requesttype
dframe["RESPONSECODE"] = responsecode
dframe["BYTES"] = bytes1
dframe["REFERER"] = referer
dframe.to_csv("D:\\Dataset_final.csv")

""" Selecting query field and tokenizing each word in URL query field and using word2vec NLP model to convert text to numbers """

df = pd.read_csv("D:/Dataset_final.csv")
df.head()

df.shape
tokenized = []
from nltk.tokenize import word_tokenize       

for line in df["url query"]:
     tokenized.append(word_tokenize(line))


import gensim
from gensim.test.utils import common_texts
model = gensim.models.Word2Vec(tokenized,size=150, window=10, min_count=1, sg=1, workers=10)
w2v = dict(zip(model.wv.index2word, model.wv.syn0))
print(common_texts)

x = model.wv.index2word

A = []

for lst in tokenized:
    a = [0]*34862
    for token in lst:
        a[x.index(token)] = 1
    A.append(a)

import numpy as np
A = np.array(A)
B = np.array(model.wv.syn0)
C = A.dot(B)

""" Now, we have datset containing numericals, let's use SVM classification model to perform learning"""
dataset = pd.read_csv('D:/payload_final.csv')
y = dataset.iloc[:,7].values
from sklearn.preprocessing import LabelEncoder, OneHotEncoder

onehotencoder = OneHotEncoder(categorical_features = [0])

labelencoder_y = LabelEncoder()
y = labelencoder_y.fit_transform(y)

print(y)

"""Splitting data into training and test set """

from sklearn.model_selection import train_test_split
C_train, C_test, y_train, y_test = train_test_split(C, y, test_size = 0.25, random_state=0)

from sklearn.svm import SVC
classifier = SVC(kernel = 'linear', random_state = 0)
classifier.fit(C_train, y_train)

y_pred = classifier.predict(C_test)

""" Identify false positive ratio using confusion matrix"""

from sklearn.metrics import confusion_matrix
cm = confusion_matrix(y_test, y_pred)

""" Predicting the results based on model learning"""
y_prediction = classifier.predict()



