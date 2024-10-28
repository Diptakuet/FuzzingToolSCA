Number of samples: 2400
Features per sample: 4 
Feature 1 = Event1 = 'br_inst_retired.all_branches'
Feature 2 = Event2 = 'br_misp_retired.all_branches'
Feature 3 = Event3 = 'cache-misses'
Feature 4 = Event4 = 'cache-references'

X.csv--> Entire dataset (2400 x 4) 
     First 1200 samples belong to benign data and the rest 1200 refers to attack data
Y.csv--> Label of the data (2400 x 1)
     Each benign sample is labeled as '0' and each attack sample is labeled as '1'

x_train.csv--> 80% of X
y_train.csv--> 80% of Y

x_test.csv--> 20% of X
y_test.csv--> 20% of X

////replace 'x_test' with your new data and check the prediction of detection tool///





