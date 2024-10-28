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


class DetectionModel2:
    def __init__(self, test_data_with_path):
        data_path = 'D:\CPR Research\Topic8. Adversarial_attack\myversion\Fuzzing_tool\Tested_Detection_models\Model_2\X_train.csv'
        self.x_train=pd.read_csv(os.path.join(data_path,"X_train.csv"),header=None)
        test_data=pd.read_csv(test_data_with_path)
        test_data.to_csv(os.path.join(data_path,"X_test.csv"), index=False, header=False) # Overwrite X_test.csv with the given file path)
        self.x_test=pd.read_csv(os.path.join(data_path,"X_test.csv"),header=None)
        self.x_train = self.x_train.to_numpy()
        self.x_test = self.x_test.to_numpy()

        #print("X_test: ", x_test.shape)
        samples=self.x_train.shape[1]


        self.x_train = self.x_train.reshape(self.x_train.shape[0], samples, 1).astype("float32")
        self.x_test = self.x_test.reshape(self.x_test.shape[0], samples,1).astype("float32")



        self.x_test = (self.x_test-self.x_train.mean())/self.x_train.std()



        model = tf.keras.models.load_model(os.path.join(data_path,"Model1.h5"))
        #model.summary()


        predict_x=model.predict(self.x_test) 
        classes_x=np.argmax(predict_x,axis=1)
        print("Prediction:\n",classes_x)
        
        return classes_x

