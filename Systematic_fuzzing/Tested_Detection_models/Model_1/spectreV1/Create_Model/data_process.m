clc;clear all;
cd 'D:\CPR Research\Topic8. Adversarial_attack\Detection_model_1\ML_models';
disp("Setup Ready!!")
path_attack_files='/home/mais_lab/Detection_model/Data/only_attack/';
path_benign_files='/home/mais_lab/Detection_model/Data/benign_load/';

attack_files=dir(strcat(path_attack_files,'*.csv'));
no_load_files=dir(strcat(path_no_load_files,'*.csv'));
benign_files=dir(strcat(path_benign_files,'*.csv'));


% Reading all the attack files
elements=200;
i=1;
for k=1:length(attack_files)
   data=readmatrix(strcat(path_attack_files,(attack_files(k).name)));
   attack(:,k)=data(1:elements,2);
   clear data;
end
attack=reshape(attack,[elements*length(attack_files),1]);

% -----------------------------------------------------------
% Extracting feature vector for each sample
% overall size 4800
% num_event = 4
% num_sample = 4800/4 = 1200
% X_attack=size(num_sample,num_event)
% -----------------------------------------------------------

num_event=4; k=1;
for i=1:4:length(attack)
    X_attack(k,:)=attack(i:i+num_event-1);
    k=k+1; 
end


% Reading all the benign files
elements=200;
i=1;
for k=1:length(benign_files)
   data=readmatrix(strcat(path_benign_files,(benign_files(k).name)));
   benign(:,k)=data(1:elements,2);
   clear data;
end
benign=reshape(benign,[elements*length(benign_files),1]);

% -----------------------------------------------------------
% Extracting feature vector for each sample
% overall size 4800
% num_event = 4
% num_sample = 4800/4 = 1200
% X_benign=size(num_sample,num_event)
% -----------------------------------------------------------

num_event=4; k=1;
for i=1:4:length(benign)
    X_benign(k,:)=benign(i:i+num_event-1);
    k=k+1; 
end

%% X and Y
X=[X_benign;X_attack];

y_benign=zeros(length(X_benign),1);
y_attack=ones(length(X_attack),1);
Y=[y_benign;y_attack];

%% Spliting Data
% Partiion with 20% data as testing 
hpartition = cvpartition(size(X,1),'Holdout',0.2); 
% Extract indices for training and test 
trainId = training(hpartition);
testId = test(hpartition);
% Use Indices to parition the matrix  
x_train = X(trainId,:);
x_test = X(testId,:);
y_train = Y(trainId, :);
y_test = Y(testId, :);

%% Save
cd '/home/mais_lab/Detection_model/ML_models/FinalData';
writematrix(X,strcat('X.csv'));
writematrix(Y,strcat('Y.csv'));
%writematrix(x_train,strcat('X_train.csv'));
%writematrix(y_train,strcat('Y_train.csv'));
writematrix(x_test,strcat('X_test.csv'));
writematrix(y_test,strcat('Y_test.csv'));

