import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split


####################################################################################
# Benign Data
# Num of test: 20
# Num of sample/test: 50
# Total sample: 1000
####################################################################################

# Data path
num_sample = 50
benign_data_path = 'D:/CPR Research/Topic8. Adversarial_attack/myversion/Fuzzing_tool/Tested_Detection_models/Model_2/spectreV1/Create_Model/Processed_Data/benign'
file_names = [file for file in os.listdir(benign_data_path) if file.endswith('.txt')]

X = pd.DataFrame()
Y = pd.DataFrame()

# Path of the processed data (where the data will be saved)
processed_data_path = 'D:/CPR Research/Topic8. Adversarial_attack/myversion/Fuzzing_tool/Tested_Detection_models/Model_2/spectreV1/Create_Model/Processed_Data/FinalData'

for file_name in file_names:
    # Read the raw data
    df = pd.read_csv(os.path.join(benign_data_path, file_name), header=None)
    # Filtering out the zeros and Reset index.  
    # Comment in for the attack
    # df= df[df != 0].dropna()
    # df = df.reset_index(drop=True)

    if len(df) >= num_sample:
        df = df[0:num_sample]
    else:
        print("Expect more benign samples:", file_name)

        exit()

    X = pd.concat([X, df])
    Y = pd.concat([Y, pd.DataFrame(np.zeros(df.shape[0]))])  



####################################################################################
# Attack Data
# Num of atttack: 2 (spectre v1)
# Num of sample/attack: 1000
# Total sample: 1000
####################################################################################


# Add the code for the attack data
attack_data_path = 'D:/CPR Research/Topic8. Adversarial_attack/myversion/Fuzzing_tool/Tested_Detection_models/Model_2/spectreV1/Create_Model/Processed_Data/attack'
attack_file_name_specv1 = 'spectre_v1.txt' 
#attack_file_name_specv2 = 'spectre_v2.txt' 
num_sample = 1000

df_specv1 = pd.read_csv(os.path.join(attack_data_path, attack_file_name_specv1), header=None)
#df_specv2 = pd.read_csv(os.path.join(data_path, attack_file_name_specv2), header=None)

# Filtering out the zeros and Reset index.  
# Comment in for the attack

def attack_data_process(df):
    df = df[df != 0].dropna()
    df = df.reset_index(drop=True)

    if len(df) > num_sample:
        df = df[0:num_sample]
    else:
        print("Expect more attack samples")
        exit()
    return df


df_spec_v1=attack_data_process(df_specv1)
#df_spec_v2=attack_data_process(df_specv2)



X = pd.concat([X, df_spec_v1])
Y = pd.concat([Y, pd.DataFrame(np.ones(df_spec_v1.shape[0]))])  



# print("Spectre v1:\n",df_spec_v1)
# print("Spectre v2:\n",df_spec_v2)


# Split the data
X_train, X_temp, Y_train, Y_temp = train_test_split(X, Y, test_size=0.2, random_state=42)
X_val, X_test, Y_val, Y_test = train_test_split(X_temp, Y_temp, test_size=0.5, random_state=42)

# Print the shapes of the datasets
print("Train data shapes:", X_train.shape, Y_train.shape)
print("Validation data shapes:", X_val.shape, Y_val.shape)
print("Test data shapes:", X_test.shape, Y_test.shape)


# Save the data
X.to_csv(os.path.join(processed_data_path, "X.csv"), header=None, index=False)
Y.to_csv(os.path.join(processed_data_path, "Y.csv"), header=None, index=False)
X_train.to_csv(os.path.join(processed_data_path, "X_train.csv"), header=None, index=False)
Y_train.to_csv(os.path.join(processed_data_path, "Y_train.csv"), header=None, index=False)
X_test.to_csv(os.path.join(processed_data_path, "X_test.csv"), header=None, index=False)
Y_test.to_csv(os.path.join(processed_data_path, "Y_test.csv"), header=None, index=False)
X_val.to_csv(os.path.join(processed_data_path, "X_val.csv"), header=None, index=False)
Y_val.to_csv(os.path.join(processed_data_path, "Y_val.csv"), header=None, index=False)