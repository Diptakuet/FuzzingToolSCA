###############################################################################################
#  MODIFICATION HISTORY:
# 
#  Ver          Who       Date	      Changes
#  -----        --------- ---------- ----------------------------------------------
#  1.00         Debopriya 6/15/2024  Created the file
###############################################################################################


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
from sklearn.linear_model import LogisticRegressionCV
from sklearn.neural_network import MLPClassifier
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.model_selection import train_test_split
from sklearn.datasets import make_classification
import tensorflow as tf
from tensorflow import keras
from keras import datasets, layers, models
import h5py


from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler



class DetectionModel_4_spectre2:

    def __init__(self,test_file_name, experiment_name, attack_name):
        data_path = f"D:/CPR Research/Topic8. Adversarial_attack/FinalWorkDir/Systematic_fuzzing/Tested_Detection_models/Model_4/{attack_name}"
        self.model_path=f"D:/CPR Research/Topic8. Adversarial_attack/FinalWorkDir/Systematic_fuzzing/Tested_Detection_models/Model_4/{attack_name}/Create_Model/Processed_Data/Model_{attack_name}.h5"
        # for accuracy check
        #data_path = f"D:/CPR Research/Topic8. Adversarial_attack/FinalWorkDir/Systematic_fuzzing/Tested_Detection_models/Model_4/{attack_name}/Create_Model/Processed_Data"
        test_data_with_path=f"{data_path}/Test_Data/moduletest/{experiment_name}/{test_file_name}"
        events=['PAPI_L3_TCA','PAPI_L3_TCM','PAPI_BR_INS','PAPI_BR_MSP','PAPI_TOT_INS']
        test_data=pd.read_csv(test_data_with_path)
        test_data=test_data[test_data != 0].dropna()
        test_data=test_data[events]
        test_data.to_csv(os.path.join(data_path,"X_test.csv"), index=False, header=False) # Overwrite X_test.csv with the given file path)
        self.x_train=pd.read_csv(os.path.join(data_path,"X_train.csv"),header=None)
        self.x_test=pd.read_csv(os.path.join(data_path,"X_test.csv"),header=None)
        self.x_test = self.x_test.to_numpy()
        self.x_train = self.x_train.to_numpy()

        self.y_train=pd.read_csv(os.path.join(data_path,"Y_train.csv"),header=None)
        self.y_test=pd.read_csv(os.path.join(data_path,"Y_test.csv"),header=None)

        self.y_train.columns=['y']
        self.y_test.columns=['y']

    




    # Buliding SVM model
    def svm_model(self):
        x_train = (self.x_train-self.x_train.mean())/self.x_train.std()
        x_test = (self.x_test-self.x_train.mean())/self.x_train.std()
        svm_model = SVC(kernel='rbf', gamma='auto')
        svm_model.fit(x_train, self.y_train['y'])
        # Prediction
        y_pred = svm_model.predict(x_test)
        # acc=metrics.accuracy_score(self.y_test['y'], y_pred)
        print("I am here!!!")
        return y_pred #, acc

    # Buliding Logistic Regression model
    def lr_model(self):
        x_train = (self.x_train-self.x_train.mean())/self.x_train.std()
        x_test = (self.x_test-self.x_train.mean())/self.x_train.std()
  
        lr_model = LogisticRegression(C=1e6, random_state=0).fit(x_train,self.y_train['y'])
        # Prediction
        y_pred = lr_model.predict(x_test)
        #acc=metrics.accuracy_score(self.y_test, y_pred)
        return y_pred#, acc

    # Buliding Logistic Regression model
    def lda_model(self):
        x_train = (self.x_train-self.x_train.mean())/self.x_train.std()
        x_test = (self.x_test-self.x_train.mean())/self.x_train.std()
        lda_model = LinearDiscriminantAnalysis(solver="lsqr", shrinkage=None).fit(x_train,self.y_train['y'])
        # Prediction
        y_pred = lda_model.predict(x_test)
        #acc=metrics.accuracy_score(self.y_test, y_pred)
        return y_pred#, acc

    # Buliding cnn model
    def cnn_model(self):
        #model_path=f"D:/CPR Research/Topic8. Adversarial_attack/FinalWorkDir/Systematic_fuzzing/Tested_Detection_models/Model_4/{attack_name}/Create_Model/Processed_Data"
        x_train = (self.x_train-self.x_train.mean())/self.x_train.std()
        x_test = (self.x_test-self.x_train.mean())/self.x_train.std()
        
        x_train = x_train.reshape(x_train.shape[0], x_train.shape[1], 1).astype("float32")
        x_test = x_test.reshape(x_test.shape[0], x_train.shape[1],1).astype("float32")
        y_test = tf.keras.utils.to_categorical(self.y_test)

        cnn_model = tf.keras.models.load_model(os.path.join(self.model_path))
        # verify accuracy
        #score = cnn_model.evaluate(x_test, y_test, verbose=0)
        #print("Test accuracy:", score[1])
        # Prediction
        y_pred = cnn_model.predict(x_test)
        classes_x=np.argmax(y_pred,axis=1)
        return classes_x#, score[1]


    def attack_code_detected(detection_results_np_arr, window_width=10, acceptable_high_threshold=0.9, acceptable_mid_threshold=0.5):
        """
        This function takes in a np array, and an int of the width of a running window, and
        two floats with the acceptable thresholds. If the window's average is greater than or
        equal to the acceptable_high_threshold, it returns "High". If it's less than the
        acceptable_high_threshold but greater than or equal to the acceptable_mid_threshold,
        it returns "Mid". Otherwise, it returns "Low".

        This method/function is partially written by, or written with the aid of, ChatGPT.
        """
    # Iterate through the array with a window of window_width elements

        toReturn = "Low" # Default to "Low"
    
        for i in range(len(detection_results_np_arr) - (window_width - 1)):
            # Calculate the average of the current window
            window_average = np.mean(detection_results_np_arr[i:i + window_width])
            # Check if the average is greater than or equal to the high threshold
            if window_average >= acceptable_high_threshold:
                toReturn = "High"
            # Check if the average is between the high threshold and the mid threshold
            elif window_average >= acceptable_mid_threshold:
                if (toReturn != "High"): toReturn = "Mid"               # We only want to highest rating

        # If no window meets the condition, return "Low"
        # if (toReturn != "High" or toReturn != "Mid"): toReturn = "Low"  # We only want to highest rating

        return toReturn








