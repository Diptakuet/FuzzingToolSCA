clc;clear all;close all;

cd 'D:\CPR Research\Topic8. Adversarial_attack\myversion\Fuzzing_tool\modules\analysis';


%% Cache-misses
% cache_files=dir('cache_data_*');
% time_files=dir('cache_misses_op_time_*');
% i=1;
% for k=1:length(cache_files)
%    data=readmatrix(cache_files(k).name);
%    cache_miss(:,k)=data(:,1);
%    cache_ref(:,k)=data(:,2);
%    clear data;
% end
% 
% 
% for k=1:length(time_files)
%    data_time=readmatrix(time_files(k).name);
%    time(:,k)=data_time(:,1);
%    clear data_time;
% end
% 
% 
% LEN=10000:20000:200000;
% cache_misses=mean(cache_miss,2);
% cache_reference=mean(cache_ref,2);
% time_mean=mean(time,2);
% y=[cache_misses cache_reference];
% figure(1);
% bar(LEN,y);
% hold on;
% yyaxis right;
% plot(LEN,time_mean);
% ylabel('Operation Time (ms)')
% legend('cache\_misses','cache\_reference');
% xlabel('Memory Initialization in bytes (LEN)');
% yyaxis left;
% ylabel('Counter value');
%% br_inst_retired
clc;close all;
b=readmatrix("br_inst_counter.txt");
time=readmatrix("br_inst_op_time.txt");
iteration=10000:10000:100000;

figure(2);
bar(iteration,b);
hold on;
yyaxis right;
plot(iteration,time);
ylabel('Operation Time (ms)')
legend('br\_inst\_retired.all\_branches');
xlabel('Number of loop iteration');
yyaxis left;
ylabel('Counter value');
%ylim([10^7 10^10]);


%% br_misp_retired
close all;
bm=readmatrix("br_misp_1.txt");
bm=bm(:,1);

time=readmatrix("br_misp_3.txt");
iteration=10000:10000:100000;

figure(3);
bar(iteration,bm);
hold on;
yyaxis right;
plot(iteration,time);
ylabel('Operation Time (ms)')
legend('br\_misp\_retired.all\_branches');
xlabel('Number of loop iteration');
yyaxis left;
ylabel('Counter value');
