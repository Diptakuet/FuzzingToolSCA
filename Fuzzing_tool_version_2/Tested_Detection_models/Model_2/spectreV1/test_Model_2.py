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
import time
from loguru import logger
from datetime import datetime
import os
import numpy as np


'''
#experiment_name = "cache_misses" # This will become file names so don't put illegal symbols
experiment_name = "" # This will become file names so don't put illegal symbols
#experiment_name = "br_inst_retired" # This will become file names so don't put illegal symbols
#experiment_name = "br_misp_retired" # This will become file names so don't put illegal symbols
test_file_name = "PAPI_data_0.csv"
'''


def prediction_test_data(test_file_name, experiment_name):
    data_path = 'D:/CPR Research/Topic8. Adversarial_attack/myversion/Fuzzing_tool/Tested_Detection_models/Model_2'
    test_data_with_path=f"{data_path}/Test_data/moduletest/{experiment_name}/{test_file_name}"
    events=['PAPI_L3_TCA','PAPI_L3_TCM','PAPI_TOT_INS']
    
    test_data=pd.read_csv(test_data_with_path)
    test_data=test_data[events]
    test_data.to_csv(os.path.join(data_path,"X_test.csv"), index=False, header=False) # Overwrite X_test.csv with the given file path)
    x_train=pd.read_csv(os.path.join(data_path,"X_train.csv"),header=None)
    x_test=pd.read_csv(os.path.join(data_path,"X_test.csv"),header=None)
    x_test = x_test.to_numpy()
    x_train = x_train.to_numpy()



    print("X_test: ", test_data.shape)


    samples=x_train.shape[1]


    x_train = x_train.reshape(x_train.shape[0], samples, 1).astype("float32")
    x_test = x_test.reshape(x_test.shape[0], samples,1).astype("float32")


    x_test = (x_test-x_train.mean())/x_train.std()



    model = tf.keras.models.load_model(os.path.join(data_path,"Model1.h5"))
    #model.summary()

    predict_x=model.predict(x_test) 
    classes_x=np.argmax(predict_x,axis=1)

    return classes_x



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


## Main Func()





'''
prediction_result=prediction_test_data(test_file_name, experiment_name)
print(prediction_result)
detection_outcome=attack_code_detected(prediction_result)

if detection_outcome != 'Low':
    print('The attack is detected with ' + str(detection_outcome) + ' confidence')
else:
    print('The attack is not detected!!\n')
    print('!!!!!!!!!Fuzzing Successfull!!!!!!!!')
    
'''