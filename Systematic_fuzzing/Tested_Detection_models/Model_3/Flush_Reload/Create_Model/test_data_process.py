import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

#########################################
# Benign Apps = 16
# Total Measure/app = x
# Num of samples/Measure = 1000
# Num of expected samples = 50000
# Num of expected samples = Benign Apps*(Num of samples/Measure)*(Total Measure/app)
# x = 50000/(16*1000) 
# unexpected_sample = int(x/(Num of samples/Measure))   (Leakage Output)
# num_sample = x + unexpected_sample
#########################################



# Data path
num_sample = 3129
data_path = 'D:/CPR Research/Topic8. Adversarial_attack/myversion/Fuzzing_tool/Tested_Detection_models/Model_3/Flush_Reload/Create_Model/Data/benign'
file_names = [file for file in os.listdir(data_path) if file.endswith('.txt')]

X = pd.DataFrame()
Y = pd.DataFrame()
columns=['PAPI_TOT_CYC', 'PAPI_L1_DCM', 'PAPI_L3_TCM', 'PAPI_L3_TCA']


# Path of the processed data (where the data will be saved)
processed_data_path = 'D:\CPR Research\Topic8. Adversarial_attack\myversion\Fuzzing_tool\Tested_Detection_models\Model_3\Flush_Reload\Create_Model\Processed_Data'


for file_name in file_names:
    # Read the raw data
    df = pd.read_csv(os.path.join(data_path, file_name),delimiter=', ', names=columns)
    #print("File Name:", file_name)
    # Check Number of samples. Initial scrutiny
    if len(df) > num_sample:
        df = df[0:num_sample]
    else:
        print("Expect more samples")
        exit()

    # Omiting the Key leakage output
    c=0
    mark_index=[]
    for i in range(0,num_sample,1000):
        if (i != 0):
            mark_index.append(i+c)
            c=c+1
                      
    #print(mark_index)
    #print(df.loc[mark_index])

    df=df.drop(mark_index)

    # Ensure all data is numeric, coerce errors to NaN
    for col in columns:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    df_diff = df.diff().iloc[1:]
    df_diff = df_diff.reset_index(drop=True)

    X = pd.concat([X, df_diff])
    Y = pd.concat([Y, pd.DataFrame(np.zeros(df_diff.shape[0]))])  # Corrected error


# Save the data
X.to_csv(os.path.join(processed_data_path, "X.csv"), index=False)
Y.to_csv(os.path.join(processed_data_path, "Y.csv"), header=None, index=False)


print(X.shape)
print(Y.shape)


# Add the code for the attack data
attack_data_path = 'D:/CPR Research/Topic8. Adversarial_attack/myversion/Fuzzing_tool/Tested_Detection_models/Model_3/Flush_Reload/Create_Model/Data/attack'

attack_file_names = [file for file in os.listdir(attack_data_path) if file.endswith('.txt')]

#num_sample = 1000


for file_name in attack_file_names:
    # Read the raw data
    df = pd.read_csv(os.path.join(attack_data_path, file_name),delimiter=', ')
    #print("File Name:", file_name)

    num_sample=len(df)
    c=0
    mark_index=[]
    for i in range(0,num_sample,1000):
        if (i != 0):
            mark_index.append(i+c)
            c=c+1
                      
    #print(mark_index)
    #print(df.loc[mark_index])

    df=df.drop(mark_index)

    # Ensure all data is numeric, coerce errors to NaN
    for col in columns:
        df[col] = pd.to_numeric(df[col], errors='coerce')


    df_diff = df.diff().iloc[1:]
    df_diff = df_diff.reset_index(drop=True)

    # Merge data from all files
    X = pd.concat([X, df_diff])
    Y = pd.concat([Y, pd.DataFrame(np.ones(df_diff.shape[0]))])  # Corrected error


X = X[:100000]
Y = Y[:100000]
print(X)
print(Y)
print(X.shape)
print(Y.shape)

# Save the data
X.to_csv(os.path.join(processed_data_path, "X.csv"), index=False)
Y.to_csv(os.path.join(processed_data_path, "Y.csv"), header=None, index=False)

print(X.shape)
print(Y.shape)


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
