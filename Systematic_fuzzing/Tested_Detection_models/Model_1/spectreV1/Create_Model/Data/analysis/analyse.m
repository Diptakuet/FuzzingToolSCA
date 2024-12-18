clc;clear all;close all;
cd 'D:\CPR Research\Topic8. Adversarial_attack\Detection_model_1\Data\analysis';
path_attack_files='';

attack_files=dir(strcat(path_attack_files,'*.csv'));



% Reading all the attack files
i=1; attack={};
for k=1:length(attack_files)
   data=readmatrix(strcat(path_attack_files,(attack_files(k).name)));
   attack{end+1}=data(:,2);
   clear data;
end
%attack=reshape(attack,[elements*length(attack_files),1]);

% -----------------------------------------------------------
% Extracting feature vector for each sample
% overall size 4800
% num_event = 4
% num_sample = 4800/4 = 1200
% X_attack=size(num_sample,num_event)
% Feature 1 = Event1 = 'br_inst_retired.all_branches'
% Feature 2 = Event2 = 'br_misp_retired.all_branches'
% Feature 3 = Event3 = 'cache-misses'
% Feature 4 = Event4 = 'cache-references'
% -----------------------------------------------------------
%%

% Counters while the system is in attack

instance=1;
event1=1;
event2=2;
event3=3;
event4=4;
num_event=4;

br_inst_retired_all_branches_attack=mean(attack{instance}(event1:num_event:length(attack{instance})));
br_misp_retired_all_branches_attack=mean(attack{instance}(event2:num_event:length(attack{instance})));
cache_misses_attack=mean(attack{instance}(event3:num_event:length(attack{instance})));
cache_references_attack=mean(attack{instance}(event4:num_event:length(attack{instance})));

figure(1);
y=[cache_misses_attack cache_references_attack br_misp_retired_all_branches_attack br_inst_retired_all_branches_attack; ...
    mean(attack{instance+1}(event3:num_event:length(attack{instance+1}))) mean(attack{instance+1}(event4:num_event:length(attack{instance+1}))) ...
    mean(attack{instance+1}(event2:num_event:length(attack{instance+1}))) mean(attack{instance+1}(event1:num_event:length(attack{instance+1}))); ...
    mean(attack{instance+2}(event3:num_event:length(attack{instance+2}))) mean(attack{instance+2}(event4:num_event:length(attack{instance+2}))) ...
    mean(attack{instance+2}(event2:num_event:length(attack{instance+2}))) mean(attack{instance+2}(event1:num_event:length(attack{instance+2})));];

x=categorical({'cache-misses','cache-references','br-misp-retired.all-branches','br-inst-retired.all-branches'});

C=bar(x,y);

% figure;
% plot(br_inst_retired_all_branches_attack);
% title('br-inst-retired.all-branches');
% 
% 
% figure;
% plot(br_misp_retired_all_branches_attack);
% title('br-misp-retired.all-branches');
% 
% 
% figure;
% plot(cache_misses_attack);
% title('cache-misses');
% 
% figure;
% plot(cache_references_attack);
% title('cache-references');