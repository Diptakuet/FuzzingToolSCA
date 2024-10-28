clc;clear all;close all;
cd 'D:\CPR Research\Topic8. Adversarial_attack\Detection_model_1\ML_models\FinalData';
disp("Setup Ready!!")
disp('Detection Model 1')
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Number of samples: 2400
% Features per sample: 4 
% Feature 1 = Event1 = 'br_inst_retired.all_branches'
% Feature 2 = Event2 = 'br_misp_retired.all_branches'
% Feature 3 = Event3 = 'cache-misses'
% Feature 4 = Event4 = 'cache-references'
% 
% X.csv--> Entire dataset (2400 x 4) 
%      First 1200 samples belong to benign data and the rest 1200 refers to attack data
% Y.csv--> Label of the data (2400 x 1)
%      Each benign sample is labeled as '0' and each attack sample is labeled as '1'

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Read counter values
X=readmatrix("X.csv");
Y=readmatrix("Y.csv");

attack_index=1201:2400;
benign_index=1:1200;

% Counters while the system is in attack
br_inst_retired_all_branches_attack=mean(X(attack_index,1));
br_misp_retired_all_branches_attack=mean(X(attack_index,2));
cache_misses_attack=mean(X(attack_index,3));
cache_references_attack=mean(X(attack_index,4));

% Counters during benign condition
br_inst_retired_all_branches_benign=X(benign_index,1);
br_misp_retired_all_branches_benign=X(benign_index,2);
cache_misses_benign=X(benign_index,3);
cache_references_benign=X(benign_index,4);

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Classify them based on individual benign tests
% BENIGN APPS = 24
% SAMPLE PER BENIGN APPS = 50
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
num_benign_test=24;
sample_per_benign_test=50;
total_sample=num_benign_test*sample_per_benign_test;

k=1;
for i=1:sample_per_benign_test:total_sample
    br_inst_retired_all_branches_per_benign_test(:,k)=mean(br_inst_retired_all_branches_benign(i:i+sample_per_benign_test-1));
    br_misp_retired_all_branches_per_benign_test(:,k)=mean(br_misp_retired_all_branches_benign(i:i+sample_per_benign_test-1));
    cache_misses_per_benign_test(:,k)=mean(cache_misses_benign(i:i+sample_per_benign_test-1));
    cache_references_per_benign_test(:,k)=mean(cache_references_benign(i:i+sample_per_benign_test-1));
    k=k+1;
end

%% plot
figure(1);
C=bar(cache_references_per_benign_test);
hold on;
plot(cache_references_attack*ones(length(cache_references_per_benign_test)),'--r');
title('Cache-references');
%C(1).FaceColor = 'b';
%C(2).FaceColor = 'r';
%legend('Attack','Benign');
%title('Detection Model 1');


figure(2);
C=bar(cache_misses_per_benign_test);
hold on;
plot(cache_misses_attack*ones(length(cache_misses_per_benign_test)),'--r');
title('Cache-misses');

figure(3);
C=bar(br_inst_retired_all_branches_per_benign_test);
hold on;
plot(br_inst_retired_all_branches_attack*ones(length(br_inst_retired_all_branches_per_benign_test)),'--r');
title('br-inst-retired-all-branches');


figure(4);
C=bar(br_misp_retired_all_branches_per_benign_test);
hold on;
plot(br_misp_retired_all_branches_attack*ones(length(br_misp_retired_all_branches_per_benign_test)),'--r');
title('br-misp-retired-all-branches');



