import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from keras import datasets, layers, models
import matplotlib as mpl
import matplotlib.pyplot as plt
import h5py
import os
from sklearn.metrics import f1_score
#os.environ["CUDA_VISIBLE_DEVICES"]="-1"




data_path = 'D:/CPR Research/Topic8. Adversarial_attack/myversion/Fuzzing_tool/Tested_Detection_models/Model_2/spectreV1/Create_Model/Processed_Data/FinalData'


x_train = pd.read_csv(os.path.join(data_path,"X_train.csv"), header=None)
y_train = pd.read_csv(os.path.join(data_path,"Y_train.csv"), header=None)
x_val = pd.read_csv(os.path.join(data_path,"X_val.csv"), header=None)
y_val = pd.read_csv(os.path.join(data_path,"Y_val.csv"), header=None)
x_train = x_train.to_numpy()
x_val = x_val.to_numpy()


y_train.columns=['y']
y_val.columns=['y']

print(x_train.shape)
print(x_val.shape)
print(y_train['y'].shape)
print(y_val['y'].shape)

samples=x_train.shape[1]


x_train = x_train.reshape((x_train.shape[0], samples, 1)).astype("float32")
x_val = x_val.reshape(x_val.shape[0], samples,1).astype("float32")

# Categorical (one hot) encoding of the labels
y_train = keras.utils.to_categorical(y_train)
y_val = keras.utils.to_categorical(y_val)


mean = x_train.mean()
std = x_train.std()

x_train = (x_train-mean)/std
x_val =  (x_val-mean)/std



print(x_train.shape)
print(x_val.shape)
print(y_train.shape)
print(y_val.shape)


# Define the neural network architecture
hidden_size = 32
output_size = 2

model = models.Sequential()
model.add(tf.keras.layers.Dense(hidden_size, activation='relu', input_shape=(samples,)))
model.add(tf.keras.layers.Dense(output_size, activation='sigmoid'))
model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])



model.summary()

history = model.fit(x_train, y_train, epochs=50, validation_data=(x_val, y_val))


#np.save('History1.npy',history.history)
#model.save('Model1.h5')
model.save(os.path.join(data_path,"Model1.h5"))

score = model.evaluate(x_val, y_val, verbose=0)
#print("Test loss:", score[0])
print("Test accuracy:", score[1])


predict_x=model.predict(x_val) 
#np.savetxt('Raw_prediction.txt',predict_x)
classes_x=np.argmax(predict_x,axis=1)
print(classes_x)



'''
con_mat = tf.math.confusion_matrix(labels=y_test1, predictions=classes_x).numpy()
classes = [0,1];
con_mat_norm = np.around(con_mat.astype('float') / con_mat.sum(axis=1)[:, np.newaxis], decimals=2)

con_mat_df = pd.DataFrame(con_mat_norm,index = classes, columns = classes)
con_mat_df.to_csv('Confusion_matrix_validation.csv')

print("F1-Score:",f1_score(y_test1, classes_x, average='binary'))
'''

