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
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.datasets import make_classification



class DetectionModel_1:

    def __init__(self,test_file_name, experiment_name, attack_name):
        data_path = f"D:/CPR Research/Topic8. Adversarial_attack/FinalWorkDir/Systematic_fuzzing/Tested_Detection_models/Model_1/{attack_name}"
        test_data_with_path=f"{data_path}/Test_data/moduletest/{experiment_name}/{test_file_name}"
        events=['br_inst_retired.all_branches','br_misp_retired.all_branches','cache-misses','cache-references']
        test_data=pd.read_csv(test_data_with_path)
        test_data=test_data[events]
        test_data.to_csv(os.path.join(data_path,"X_test.csv"), index=False, header=False) # Overwrite X_test.csv with the given file path)
        self.x_train=pd.read_csv(os.path.join(data_path,"X_train.csv"),header=None)
        self.x_test=pd.read_csv(os.path.join(data_path,"X_test.csv"),header=None)
        self.x_test = self.x_test.to_numpy()
        self.x_train = self.x_train.to_numpy()
        self.y_train=pd.read_csv(os.path.join(data_path,"Y_train.csv"),header=None)
        self.y_train.columns=['y']





    # Buliding SVM model
    def svm_model(self):
        x_train = (self.x_train-self.x_train.mean())/self.x_train.std()
        x_test = (self.x_test-self.x_train.mean())/self.x_train.std()
        svm_model = SVC(kernel='rbf', gamma='auto')
        svm_model.fit(x_train, self.y_train['y'])
        # Prediction
        y_pred = svm_model.predict(x_test)
        return y_pred

    # Buliding Logistic Regression model
    def lr_model(self):
        x_train = (self.x_train-self.x_train.mean())/self.x_train.std()
        x_test = (self.x_test-self.x_train.mean())/self.x_train.std()
        lr_model = LogisticRegression(random_state=1).fit(x_train,self.y_train['y'])
        # Prediction
        y_pred = lr_model.predict(x_test)
        return y_pred


    # Buliding MLP model
    def mlp_model(self):
        x_train = (self.x_train-self.x_train.mean())/self.x_train.std()
        x_test = (self.x_test-self.x_train.mean())/self.x_train.std()
        mlp_model =MLPClassifier(random_state=1, max_iter=300).fit(x_train,self.y_train['y'])
        # Prediction
        y_pred = mlp_model.predict(x_test)
        return y_pred


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




'''
### SVM ###
print("----------------SVM--------------------------------")
prediction_result=svm_model(x_train, y_train, x_test)
print(prediction_result)
detection_outcome=attack_code_detected(prediction_result)

if detection_outcome != 'Low':
    print('The attack is detected with ' + str(detection_outcome) + ' confidence')
else:
    print('The attack is not detected!!\n')
    print('!!!!!!!!!Fuzzing Successfull!!!!!!!!')


### LR ###
print("----------------Logistic Regression----------------")
prediction_result=lr_model(x_train, y_train, x_test)
print(prediction_result)
detection_outcome=attack_code_detected(prediction_result)

if detection_outcome != 'Low':
    print('The attack is detected with ' + str(detection_outcome) + ' confidence')
else:
    print('The attack is not detected!!\n')
    print('!!!!!!!!!Fuzzing Successfull!!!!!!!!')

### MLP ###
print("----------------Multilayer Perceptron---------------")
prediction_result=mlp_model(x_train, y_train, x_test)
print(prediction_result)
detection_outcome=attack_code_detected(prediction_result)


if detection_outcome != 'Low':
    print('The attack is detected with ' + str(detection_outcome) + ' confidence')
else:
    print('\n\nThe attack is not detected!!\n\n\n')
    print('!!!!!!!!!Fuzzing Successfull!!!!!!!!')

'''