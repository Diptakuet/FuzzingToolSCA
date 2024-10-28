#!/usr/bin/env python
# coding: utf-8 

import numpy as np
import pandas as pd
import os
#os.environ["CUDA_VISIBLE_DEVICES"]="-1"
from sklearn.metrics import f1_score
from sklearn.svm import SVC
from sklearn import metrics
from sklearn.metrics import roc_curve
from sklearn.metrics import roc_auc_score
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.datasets import make_classification

# Read Data
data_path='D:\CPR Research\Topic8. Adversarial_attack\myversion\Fuzzing_tool\Tested_Detection_models\Model_1\spectreV1\Create_Model\Processed_Data'

# X=pd.read_csv(os.path.join(data_path,"X.csv"),header=None)
# Y=pd.read_csv(os.path.join(data_path,"Y.csv"),header=None)

x_train=pd.read_csv(os.path.join(data_path,"X_train.csv"),header=None)
y_train=pd.read_csv(os.path.join(data_path,"Y_train.csv"),header=None)

x_test=pd.read_csv(os.path.join(data_path,"X_test.csv"),header=None)
y_test=pd.read_csv(os.path.join(data_path,"Y_test.csv"),header=None)

# Split data
# x_train, x_test, y_train, y_test = train_test_split(X, Y, test_size=0.4,random_state=110)


# Normalize
mean=x_train.mean()
std=x_train.std()
x_train=(x_train-mean)/std
x_test=(x_test-mean)/std
y_test.columns=['y']
y_train.columns=['y']

print("x_train:", np.shape(x_train))
print("x_test:", np.shape(x_test))
print("y_train:", np.shape(y_train))
print("y_test:", np.shape(y_test))


# Buliding SVM model
def svm_model(x_train, y_train, x_test):
    svm_model = SVC(kernel='rbf', gamma='auto')
    svm_model.fit(x_train, y_train['y'])
    # Prediction
    y_pred = svm_model.predict(x_test)
    return y_pred


# Buliding Logistic Regression model
def lr_model(x_train, y_train, x_test):
    lr_model = LogisticRegression(random_state=1, max_iter=300).fit(x_train,y_train['y'])
    # Prediction
    y_pred = lr_model.predict(x_test)
    return y_pred



# Buliding MLP model
def mlp_model(x_train, y_train, x_test):
    mlp_model =MLPClassifier(random_state=1, max_iter=300).fit(x_train,y_train['y'])
    # Prediction
    y_pred = mlp_model.predict(x_test)
    return y_pred


# Results: Accuracy & F1-score

def print_result(y_pred,y_test):
    acc=metrics.accuracy_score(y_test, y_pred)
    f1=f1_score(y_test,y_pred)
    ROC_AUC = roc_auc_score(y_test, y_pred)
    fpr, tpr, _ = roc_curve(y_test['y'], y_pred)
    print("Accuracy: ", acc)
    print("F1-score: ", f1)
    print("ROC AUC score: %.5f" % ROC_AUC)
    print("FPR: ", fpr)
    print("TPR: ", tpr)
    # Compare prediction with original label
    print("Prediction:")
    print(y_pred)
    print("Original:")
    print(y_test.values.T)


### SVM ###
print("----------------SVM--------------------------------")
y_pred=svm_model(x_train, y_train, x_test)
print_result(y_pred, y_test)


### LR ###
print("----------------Logistic Regression----------------")
y_pred=lr_model(x_train, y_train, x_test)
print_result(y_pred, y_test)

### MLP ###
print("----------------Multilayer Perceptron---------------")
y_pred=mlp_model(x_train, y_train, x_test)
print_result(y_pred, y_test)
