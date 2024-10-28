import os
import pandas as pd
import numpy as np


# path of the raw data
path_raw = 'test_data/raw_data'
file_name='Run_2.csv' # 

# path of the processed data (where the data will be saved)
path_processed = 'test_data/processed_data'
file_name_processed = "X_test.csv"

# Read the raw data
columns = pd.read_csv(os.path.join(path_raw,file_name), nrows=1).select_dtypes("number").columns
#print(columns)
df= pd.read_csv(os.path.join(path_raw,file_name),usecols=columns)
print(df)
test_data=df.iloc[:,0].values  
#x = data[~np.isnan(data)]
print(test_data)


# % -----------------------------------------------------------
# % Extracting feature vector for each sample
# % overall size : size(test_data)
# % num_event = 4
# % num_sample = overall_size/num_event 
# % X_attack=size(num_sample,num_event)
# % -----------------------------------------------------------

overall_size = len(test_data)
num_event = 4
num_sample = int(overall_size/num_event)
x_test = np.zeros((num_sample,num_event))
k = 0
for i in range(0, overall_size, num_event):
    x_test[k, :] = test_data[i:i + num_event]
    k += 1

print(x_test.shape)
# x_test_df = pd.DataFrame(x_test)
# x_test_df.to_csv(os.path.join(path_processed, file_name_processed), header=None)


np.savetxt(os.path.join(path_processed, file_name_processed), x_test,fmt="%d", delimiter=",")
