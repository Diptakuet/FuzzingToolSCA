#!/usr/bin/env python
# coding: utf-8


import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from keras import datasets, layers, models
import matplotlib as mpl
import matplotlib.pyplot as plt
import h5py
#from sklearn.metrics import f1_score
import os
#from sklearn.metrics import classification_report

#data_path='without_core_restrict/Cascade/Mixture/2_core_data/Processed3'
#data_path='version_check'
data_path='D:/CPR Research/Topic8. Adversarial_attack/myversion/Fuzzing_tool/Tested_Detection_models/Model_4/spectreV1'#/Create_Model/Processed_Data'
num_image=2


x_train=pd.read_csv(os.path.join(data_path,"X_train.csv"),header=None)
x_test=pd.read_csv(os.path.join(data_path,"X_test.csv"),header=None)
y_test1=pd.read_csv(os.path.join(data_path,"Y_test.csv"),header=None)
x_test = x_test.to_numpy()
x_train = x_train.to_numpy()
y_test1.columns=['y']


print("X_test: ", x_test.shape)
print("Y_test: ", y_test1['y'].shape)

samples=x_train.shape[1]


x_train = x_train.reshape(x_train.shape[0], samples, 1).astype("float32")
x_test = x_test.reshape(x_test.shape[0], samples,1).astype("float32")
# Categorical (one hot) encoding of the labels
y_test = tf.keras.utils.to_categorical(y_test1)



x_test = (x_test-x_train.mean())/x_train.std()



model = tf.keras.models.load_model(os.path.join(data_path,"Model_spectreV1.h5"))
#model.summary()

'''
with open(os.path.join(data_path,"image_list_30.txt")) as f:
    image_list = f.readlines()
'''

score = model.evaluate(x_test, y_test, verbose=0)
print("Test loss:", score[0])
print("Test accuracy:", score[1])


'''
for i in range(0,len(image_list)):
    print(i,': ',image_list[i])

print("\nTest accuracy:", score[1]*100,' %')
'''


predict_x=model.predict(x_test) 
classes_x=np.argmax(predict_x,axis=1)
print("Prediction:\n",classes_x)
#print("Original Label:\n",y_test1.values.T)
#np.savetxt(os.path.join(data_path,"Raw_Prediction.txt"), predict_x)

#print(classification_report(y_test1,classes_x))

'''
#con_mat = tf.math.confusion_matrix(labels=y_test1, predictions=classes_x).numpy()
classes = [0,1,2,3,4,5,6,7,8,9]#,10,11,12,13,14,15,16,17,18,19];

con_mat_norm = np.around(con_mat.astype('float') / con_mat.sum(axis=1)[:, np.newaxis], decimals=2)

con_mat_df = pd.DataFrame(con_mat_norm,index = classes, columns = classes)
con_mat_df.to_csv('confusion_matrix_test.csv')

print("F1-Score:",f1_score(y_test1, classes_x, average='macro'))
'''


