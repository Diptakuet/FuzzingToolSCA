import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split


# Data path
num_sample = 250
data_path = 'D:/CPR Research/Topic8. Adversarial_attack/myversion/Fuzzing_tool/Tested_Detection_models/Model_4/Create_Model/Data/benign'
file_names = [file for file in os.listdir(data_path) if file.endswith('.txt')]

X = pd.DataFrame()
Y = pd.DataFrame()

# Path of the processed data (where the data will be saved)
processed_data_path = 'D:\CPR Research\Topic8. Adversarial_attack\myversion\Fuzzing_tool\Tested_Detection_models\Model_4\Create_Model\Processed_Data'

for file_name in file_names:
    # Read the raw data
    df = pd.read_csv(os.path.join(data_path, file_name), header=None)
    # Filtering out the zeros and Reset index.  
    # Comment in for the attack
    # df= df[df != 0].dropna()
    # df = df.reset_index(drop=True)

    if len(df) > num_sample:
        df = df[0:num_sample]
    else:
        print("Expect more samples")
        exit()

    X = pd.concat([X, df])
    Y = pd.concat([Y, pd.DataFrame(np.zeros(df.shape[0]))])  # Corrected error

print(Y.shape[0])
#print(len(df))

# Save the data
X.to_csv(os.path.join(processed_data_path, "X.csv"), header=None, index=False)
Y.to_csv(os.path.join(processed_data_path, "Y.csv"), header=None, index=False)


# Add the code for the attack data
data_path = data_path = 'D:/CPR Research/Topic8. Adversarial_attack/myversion/Fuzzing_tool/Tested_Detection_models/Model_4/Create_Model/Data/attack'

attack_file_name = 'spectre_v1.txt' 
num_sample = 5000
df = pd.read_csv(os.path.join(data_path, attack_file_name), header=None)
# Filtering out the zeros and Reset index.  
# Comment in for the attack
df = df[df != 0].dropna()
df = df.reset_index(drop=True)

if len(df) > num_sample:
    df = df[0:num_sample]
else:
    print("Expect more samples")
    exit()


#print(len(df))

X = pd.concat([X, df])
Y = pd.concat([Y, pd.DataFrame(np.ones(df.shape[0]))])  # Corrected error

print(Y.shape)

# Save the data
X.to_csv(os.path.join(processed_data_path, "X.csv"), header=None, index=False)
Y.to_csv(os.path.join(processed_data_path, "Y.csv"), header=None, index=False)

X_train, X_temp, Y_train, Y_temp = train_test_split(X, Y, test_size=0.2, random_state=42)
X_val, X_test, Y_val, Y_test = train_test_split(X_temp, Y_temp, test_size=0.5, random_state=42)

# Print the shapes of the datasets
print("Train data shapes:", X_train.shape, Y_train.shape)
print("Validation data shapes:", X_val.shape, Y_val.shape)
print("Test data shapes:", X_test.shape, Y_test.shape)


# Save the data
X_train.to_csv(os.path.join(processed_data_path, "X_train.csv"), header=None, index=False)
Y_train.to_csv(os.path.join(processed_data_path, "Y_train.csv"), header=None, index=False)
X_test.to_csv(os.path.join(processed_data_path, "X_test.csv"), header=None, index=False)
Y_test.to_csv(os.path.join(processed_data_path, "Y_test.csv"), header=None, index=False)
X_val.to_csv(os.path.join(processed_data_path, "X_val.csv"), header=None, index=False)
Y_val.to_csv(os.path.join(processed_data_path, "Y_val.csv"), header=None, index=False)
