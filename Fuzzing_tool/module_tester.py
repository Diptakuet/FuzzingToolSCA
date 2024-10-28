
# Library imports
import os
import subprocess
import time
import numpy as np
from datetime import datetime
from loguru import logger
import pandas
import paramiko
import csv
import sys
import argparse
import threading
# Project imports
from utils.SshConnector import SshConnector
from utils.PerfOutputFileParser import PerfOutputFileParser
from utils.CSVGraphPlotter import CSVGraphPlotter
from utils.CSVAverager import CSVAverager
from utils.CSVAppender import CSVAppender
# from experiments import experiment_3
# from experiments import experiment_4
#from Tested_Detection_models.Model_2.NN_test import DetectionModel2 
from utils import utils
from utils.CFileFuzzer import CFileFuzzer
from utils.CustomErrors import MakeError
from utils.CustomErrors import LenLTEZeroError
from utils.CustomErrors import DataCollectShPidAttachToZeroError
from utils import settings_file_extractor
from utils import add_CSV_header
from utils import CSVComparer
from utils import ExcelCreaterFromDict

sys.path.insert(0,'D:/CPR Research/Topic8. Adversarial_attack/myversion/Fuzzing_tool/Tested_Detection_models')
from Tested_Detection_models.Model_1.spectreV1.detection_model_1 import DetectionModel_1
from Tested_Detection_models.Model_2.detection_model_2 import DetectionModel_2
from Tested_Detection_models.Model_2.spectreV2.detection_model_2 import DetectionModel_2_spectre2
#from Tested_Detection_models.Model_2.spectreV1.detection_model_2 import DetectionModel_2
#from Tested_Detection_models.Model_2.spectreV2.detection_model_2 import DetectionModel_2
from Tested_Detection_models.Model_3.Flush_Reload.detection_model_3 import DetectionModel_3
from Tested_Detection_models.Model_4.spectreV1.detection_model_4 import DetectionModel_4
from Tested_Detection_models.Model_4.spectreV2.detection_model_4 import DetectionModel_4_spectre2
from Tested_Detection_models.Model_5.spectreV1.detection_model_5 import DetectionModel_5


class ModuleTester:
    # Constructor
    def __init__(self, config_file):
        try:
            self.ssh_host, self.ssh_username, self.ssh_password, self.model_name, self.attack_name, self.HPC_FRAMEWORK= settings_file_extractor.extract_value_from_settings_file(config_file)
        except IndexError as ie:
            logger.error("(Possibly) Incorrect format of framework settings txt file!")
            ##### Get ssh connection #####
        print("host:",self.ssh_host,"\n")
        print("username:",self.ssh_username,"\n")
        print("password:",self.ssh_password,"\n")
        print("model_name:",self.model_name,"\n")
        print("attack_name:",self.attack_name,"\n")
        print("************************************************************************************************")
        self.sshConnector = SshConnector(self.ssh_host, self.ssh_username, self.ssh_password)
        self.sshConnector.connect()
        pass

        if self.attack_name=="spectreV1":
            self.target_attack = 0
        elif self.attack_name=="spectreV2":
            self.target_attack = 1
        else:
            self.target_attack=""

        if self.model_name=="Model_1":
            self.perf_HPC="br_inst_retired.all_branches,br_misp_retired.all_branches,cache-misses,cache-references"
        elif self.model_name=="Model_2":
            self.papi_events= ["PAPI_L3_TCA", "PAPI_L3_TCM", "PAPI_TOT_INS"]
        elif self.model_name=="Model_3":
            self.papi_events = ["PAPI_TOT_CYC", "PAPI_L1_DCM", "PAPI_L3_TCM", "PAPI_L3_TCA"]
        elif self.model_name=="Model_4":    
            self.papi_events= ["PAPI_L3_TCA", "PAPI_L3_TCM", "PAPI_BR_INS", "PAPI_BR_MSP", "PAPI_TOT_INS"]

    
    
    def fuzz_Module(self, initial_value, increment, experiment_name):
        self.START_MARKER = f"// >>>>> {experiment_name} fuzz start"
        self.END_MARKER = f"// >>>>> {experiment_name} fuzz end"
        HPC_COLLECT_FREQ_MS = 100
        perf_run_time_s = 40
        rapl_run_time_s = 50
        self.filename_prefix = "moduletest"

        # File/Folder Paths
        server_collecteddata_folder = f"/home/mais_lab/victim_side/{self.model_name}/Data"
        server_attack_folder = f"/home/mais_lab/victim_side/{self.model_name}/fuzzing_module_tester/{self.attack_name}"
        self.local_collecteddata_folder = f"D:/CPR Research/Topic8. Adversarial_attack/myversion/Fuzzing_tool/Tested_Detection_models/{self.model_name}/{self.attack_name}/Test_Data"
        local_perf_txt_path = ""        # Initialized in exec_perf()
        local_spectre_txt_path = ""     # Initialized in exec_perf()
        local_perf_csv_path = ""        # Initialized in exec_perf()
        server_data_collect_sh_folder = f"/home/mais_lab/victim_side/{self.model_name}/fuzzing_module_tester"
        server_data_collect_sh_collecteddata_folder = f"/home/mais_lab/victim_side/{self.model_name}/fuzzing_module_tester/collecteddata"

        local_PAPI_out_csv_path = ""    # Initialized in exec_papi()
        local_RAPL_out_csv_path = ""
        self.local_spectre_path = f"D:/CPR Research/Topic8. Adversarial_attack/myversion/Fuzzing_tool/targeted_attacks/{self.attack_name}/spectre.c"
        self.local_flush_reload_path = f"D:/CPR Research/Topic8. Adversarial_attack/myversion/Fuzzing_tool/targeted_attacks/{self.attack_name}/newspy.cpp"


        # Common settings
        AVERAGE_COUNT = 1 # Set to 1 if no need average


        # Create CFileFuzzer object for fuzzing.
        if self.attack_name == "Flush_Reload":
            cff = CFileFuzzer(self.sshConnector, self.local_flush_reload_path, server_attack_folder)
        else:
            cff = CFileFuzzer(self.sshConnector, self.local_spectre_path, server_attack_folder)


        if self.sshConnector.getSshConnectionStatus() is True:
            def fuzz(experiment_name, initial_value, increment):
                """
                This function is to do what the framework is supposed to do: Add fuzzing instructions
                and scp the modified spectre to the server and compile it, so that the "exec_" functions
                can execute it and profile it.
                """
                cff.insertProfilingStuff()

                if experiment_name == "cache_misses":
                    cff.setInitialLENForCacheMisses(initial_value)
                    cff.increaseCacheMisses(increment, extraPrints=False)

                if experiment_name == "br_inst_retired":
                    cff.increaseBranchInstRetiredAllBranches(initial_value,extraPrints=False)
                
                if experiment_name == "br_misp_retired":
                    cff.impactBranchMissPredictRetired(initial_value,extraPrints=False)

                if experiment_name == "total_inst_retired":
                    cff.decreaseTotalInstrCompleted(initial_value,extraPrints=False)

                if experiment_name == "randomize_attack":
                    cff.randomizingAttackPerEncryption(initial_value,extraPrints=False)


                ##################################################################
            
            def exec_perf(): # Did this so I can collapse the whole thing
                """
                This function run perf AVERAGE_COUNT times, and average the results into a file.
                This function just run the attack code and the profiling tool, it doesn't compile the
                code or anything.

                @return file name of the averaged results
                """
                #                                   ______  
                #                                  /      \ 
                #     ______    ______    ______  /$$$$$$  |
                #    /      \  /      \  /      \ $$ |_ $$/ 
                #   /$$$$$$  |/$$$$$$  |/$$$$$$  |$$   |    
                #   $$ |  $$ |$$    $$ |$$ |  $$/ $$$$/     
                #   $$ |__$$ |$$$$$$$$/ $$ |      $$ |      
                #   $$    $$/ $$       |$$ |      $$ |      
                #   $$$$$$$/   $$$$$$$/ $$/       $$/       
                #   $$ |                                    
                #   $$ |                                    
                #   $$/                                     
                # Lets start by collecting perf data
                
                list_of_runs = []
                
                for i in range(0, AVERAGE_COUNT):
                    # Get time
                    timenow = datetime.now()
                    #formatted_timenow = timenow.strftime("%Y_%m%d_%H%M_%S")
                    
                    perf_command = f"perf stat -a -e {self.perf_HPC} -I {HPC_COLLECT_FREQ_MS}"

                    # Run perf and output it to a temp file
                    perf_output_temp_file = f"~perf_data_{i}.txt"
                    perf_output_temp_path = f"{server_collecteddata_folder}/{perf_output_temp_file}"
                    self.sshConnector.execute_sudo_command_nonblocking_nonlive(f"{perf_command} 2> {perf_output_temp_path}", self.ssh_password, timeout=perf_run_time_s)
                    
                    # Wait a bit so perf started
                    time.sleep(1)

                    # Run spectre
                    spectre_output_temp_file = f"~{self.filename_prefix}_{experiment_name}_attack_output_{i}.txt"
                    spectre_output_temp_path = f"{server_collecteddata_folder}/{spectre_output_temp_file}"
                    self.sshConnector.execute_command(f"(cd {server_attack_folder} && ./spectre > {spectre_output_temp_path})", wantPrint=False)

                    perf_output_local_folder = f"{self.local_collecteddata_folder}/{self.filename_prefix}/{experiment_name}"

                    # Check if the new file already exists
                    if os.path.exists(f"{perf_output_local_folder}/{perf_output_temp_file}"):
                        os.remove(f"{perf_output_local_folder}/{perf_output_temp_file}")  # Remove it if it exists


                    # Copy this temp files over
                    self.sshConnector.scp_get(perf_output_temp_path, perf_output_local_folder)
                    
                    
                    attack_output_local_folder = f"{self.local_collecteddata_folder}/{self.filename_prefix}/{experiment_name}/attack_output"
                    # Check if the new file already exists
                    if os.path.exists(f"{attack_output_local_folder}/{spectre_output_temp_file}"):
                        os.remove(f"{attack_output_local_folder}/{spectre_output_temp_file}")  # Remove it if it exists

                    # Copy this temp files over
                    self.sshConnector.scp_get(spectre_output_temp_path, attack_output_local_folder)

                    # Rename perf's output file
                    old_name = f"{perf_output_local_folder}/{perf_output_temp_file}"
                    old_name_split = old_name.split('~')    # Remove the ~ at the beginning of the file
                    new_name = "".join(old_name_split)      # Remove the ~ at the beginning of the file
                    # Check if the new file already exists
                    if os.path.exists(new_name):
                        os.remove(new_name)  # Remove it if it exists
                    os.rename(old_name, new_name)
                    local_perf_txt_path = new_name

                    
                    # Rename spectre's output file
                    old_name = f"{attack_output_local_folder}/{spectre_output_temp_file}"
                    old_name_split = old_name.split('~')    # Remove the ~ at the beginning of the file
                    new_name = "".join(old_name_split)      # Remove the ~ at the beginning of the file
                    # Check if the new file already exists
                    if os.path.exists(new_name):
                        os.remove(new_name)  # Remove it if it exists
                    os.rename(old_name, new_name)
                    local_spectre_txt_path = new_name

                    # Delete perf and spectre temp files in the server
                    self.sshConnector.execute_command(f"rm {perf_output_temp_path} && rm {spectre_output_temp_path}")


                    # Parse perf's output (turn collected txt into csv)
                    local_perf_txt_path_split = local_perf_txt_path.split(".txt")
                    local_perf_csv_path = "".join(local_perf_txt_path_split) + ".csv"
                    pofp = PerfOutputFileParser(local_perf_txt_path, local_perf_csv_path)

                    # Add to list of runs, for averaging multiple runs
                    list_of_runs.append(local_perf_csv_path)

                # Average results if more than one test was ran
                if (AVERAGE_COUNT > 1):
                    logger.debug("Averaging all perf results...")

                    # Get new time
                    timenow = datetime.now()
                    formatted_timenow = timenow.strftime("%Y_%m%d_%H%M_%S")

                    # Average results
                    averaged_csv_path = f"{self.local_collecteddata_folder}/{self.filename_prefix}/{experiment_name}/avged_perf_out_{i}.csv"
                    csva = CSVAverager(list_of_runs, averaged_csv_path)
                    logger.debug("Perf averaged!")

                    return averaged_csv_path
                else:
                    return list_of_runs[0] # Since there is only one just return the one
                         
            def exec_papi(): # Did this so I can collapse the whole thing
                """
                This function run PAPI AVERAGE_COUNT times, and average the results into a file.
                This function just run the attack code and the profiling tool, it doesn't compile the
                code or anything.

                Important: This function assumes you run exec_perf() first, so please do that.

                @return file name of the averaged results
                """
                #    _______    ______   _______   ______ 
                #   /       \  /      \ /       \ /      |
                #   $$$$$$$  |/$$$$$$  |$$$$$$$  |$$$$$$/ 
                #   $$ |__$$ |$$ |__$$ |$$ |__$$ |  $$ |  
                #   $$    $$/ $$    $$ |$$    $$/   $$ |  
                #   $$$$$$$/  $$$$$$$$ |$$$$$$$/    $$ |  
                #   $$ |      $$ |  $$ |$$ |       _$$ |_ 
                #   $$ |      $$ |  $$ |$$ |      / $$   |
                #   $$/       $$/   $$/ $$/       $$$$$$/ 
                #                                                 
                # Now lets grab PAPI's HPCs
                # Important: Unlike perf, because PAPI HPCs are collected using data_collect.sh in 
                #            /home/mais_lab/jonathan_project/fuzzing_module_tester/, so if you want to
                #            change what HPCs is collected, edit the event.conf and/or data_collect.sh
                #            there.
                list_of_runs = []
                
                for i in range(0, AVERAGE_COUNT):
                    # Get time again
                    timenow = datetime.now()
                    formatted_timenow = timenow.strftime("%Y_%m%d_%H%M_%S")
                    
                    
                    data_collect_sh_out_temp_file = f"{self.filename_prefix}_{experiment_name}_attack_output_{i}.txt"
                    data_collect_sh_exec = f"./data_collect.sh {self.target_attack} > collecteddata/{data_collect_sh_out_temp_file}"
                    self.sshConnector.execute_command(f"(cd {server_data_collect_sh_folder} && {data_collect_sh_exec})")

                    # Scp the output back (unlike my idea in exec_perf(), I realized the use of temp files are not the best idea so that wont happen again)
                    PAPI_Output_text = f"{server_data_collect_sh_collecteddata_folder}/PAPI_data.txt"
                    PAPI_output_local_folder = f"{self.local_collecteddata_folder}/{self.filename_prefix}/{experiment_name}"
                    if os.path.exists(f"{PAPI_output_local_folder}/PAPI_data.txt"):
                        os.remove(f"{PAPI_output_local_folder}/PAPI_data.txt")
                    self.sshConnector.scp_get(PAPI_Output_text, PAPI_output_local_folder)
                    old_name = f"{PAPI_output_local_folder}/PAPI_data.txt"
                    new_name = f"{PAPI_output_local_folder}/PAPI_data_{i}.csv"
                    # Check if the new file already exists
                    if os.path.exists(new_name):
                        os.remove(new_name)  # Remove it if it exists
                    os.rename(old_name, new_name)
                    local_PAPI_out_csv_path = new_name
                    server_data_collect_sh_output = f"{server_data_collect_sh_collecteddata_folder}/{data_collect_sh_out_temp_file}"
                    attack_output_local_folder = f"{self.local_collecteddata_folder}/{self.filename_prefix}/{experiment_name}/attack_output"
                    self.sshConnector.scp_get(server_data_collect_sh_output, attack_output_local_folder)

                    # Parse PAPI's output
                    add_CSV_header.add_csv_header(local_PAPI_out_csv_path, local_PAPI_out_csv_path, self.papi_events)

                    # Sometimes for some reason PAPI wont return anything, probably due to failing to latch to a PID
                    # So, here we check that if there is only 1 line in the csv, rerun:
                    line_count = 0
                    with open(local_PAPI_out_csv_path, 'r', newline='') as csvfile:
                        reader = csv.reader(csvfile)
                        line_count = sum(1 for _ in reader)
                    if (line_count < 10):
                        i -= 1
                        logger.error("Empty file. PAPI failed to find the PID")
                        continue
                   
                    # Add to list of runs, for averaging multiple runs
                    list_of_runs.append(local_PAPI_out_csv_path)

                # Average results if more than one test was ran
                if (AVERAGE_COUNT > 1):
                    logger.debug("Averaging all PAPI results...")

                    # Get new time
                    timenow = datetime.now()
                    formatted_timenow = timenow.strftime("%Y_%m%d_%H%M_%S")

                    # Average results
                    averaged_csv_path = f"{self.local_collecteddata_folder}/{self.filename_prefix}/{experiment_name}/avged_PAPI_data.csv"
                    csva = CSVAverager(list_of_runs, averaged_csv_path)
                    logger.debug("PAPI averaged!")

                    return averaged_csv_path
                else:
                    return list_of_runs[0] # Since there is only one just return the one

            def exec_rapl():
                """
                """
                list_of_runs = []
                
                for i in range(0, AVERAGE_COUNT):
                    # Get time again
                    timenow = datetime.now()
                    formatted_timenow = timenow.strftime("%Y_%m%d_%H%M_%S")
                    
                    
                    data_collect_sh_out_temp_file = f"{self.filename_prefix}_{experiment_name}_attack_output_{i}.txt"
                    data_collect_sh_exec = f"bash {server_data_collect_sh_folder}/data_collection.sh"
                    # self.sshConnector.execute_command(f"(cd {server_data_collect_sh_folder})")
                    # self.sshConnector.execute_command_v2(f"(cd {server_data_collect_sh_folder} && {data_collect_sh_exec})", password=self.ssh_password, wantPrint=True)
                    self.sshConnector.execute_sudo_command_blocking_nonlive(f"{data_collect_sh_exec} > {server_data_collect_sh_collecteddata_folder}/{data_collect_sh_out_temp_file}", self.ssh_password, timeout=rapl_run_time_s)
                    
                    # Wait a bit so perf started
                    # time.sleep(1)


                    # Scp the output back (unlike my idea in exec_perf(), I realized the use of temp files are not the best idea so that wont happen again)
                    RAPL_Output_text = f"{server_data_collect_sh_collecteddata_folder}/RAPL_data.txt"
                    RAPL_output_local_folder = f"{self.local_collecteddata_folder}/{self.filename_prefix}/{experiment_name}"
                    if os.path.exists(f"{RAPL_output_local_folder}/RAPL_data.txt"):
                        os.remove(f"{RAPL_output_local_folder}/RAPL_data.txt")
                    self.sshConnector.scp_get(RAPL_Output_text, RAPL_output_local_folder)
                    old_name = f"{RAPL_output_local_folder}/RAPL_data.txt"
                    new_name = f"{RAPL_output_local_folder}/RAPL_data_{i}.csv"
                    # Check if the new file already exists
                    if os.path.exists(new_name):
                        os.remove(new_name)  # Remove it if it exists
                    os.rename(old_name, new_name)
                    local_RAPL_out_csv_path = new_name
                    server_data_collect_sh_output = f"{server_data_collect_sh_collecteddata_folder}/{data_collect_sh_out_temp_file}"
                    attack_output_local_folder = f"{self.local_collecteddata_folder}/{self.filename_prefix}/{experiment_name}/attack_output"
                    self.sshConnector.scp_get(server_data_collect_sh_output, attack_output_local_folder)

                    # Parse PAPI's output
                    # add_CSV_header.add_csv_header(local_RAPL_out_csv_path, local_RAPL_out_csv_path, self.papi_events)

                    # Sometimes for some reason PAPI wont return anything, probably due to failing to latch to a PID
                    # So, here we check that if there is only 1 line in the csv, rerun:
                    line_count = 0
                    with open(local_RAPL_out_csv_path, 'r', newline='') as csvfile:
                        reader = csv.reader(csvfile)
                        line_count = sum(1 for _ in reader)
                    if (line_count < 10):
                        i -= 1
                        logger.error("Empty file. RAPL framework failed")
                        continue
                   

                    # Calculate energy difference
                    df= pandas.read_csv(os.path.join(local_RAPL_out_csv_path), header=None)
                    E1=df.iloc[:,0].values  
                    samples=5000
                    del_E=np.zeros(samples)
                    k=0
                    for i in range(0,samples):
                        del_E[k]=(E1[i+1]-E1[i])
                        k += 1
                    x_test_df = pandas.DataFrame(del_E).T
                    x_test_df.to_csv(os.path.join(local_RAPL_out_csv_path), header=None, index=False)

                    # Add to list of runs, for averaging multiple runs
                    list_of_runs.append(local_RAPL_out_csv_path)

                # Average results if more than one test was ran
                if (AVERAGE_COUNT > 1):
                    logger.debug("Averaging all RAPL results...")

                    # Get new time
                    timenow = datetime.now()
                    formatted_timenow = timenow.strftime("%Y_%m%d_%H%M_%S")

                    # Average results
                    averaged_csv_path = f"{self.local_collecteddata_folder}/{self.filename_prefix}/{experiment_name}/avged_PAPI_data.csv"
                    csva = CSVAverager(list_of_runs, averaged_csv_path)
                    logger.debug("RAPL averaged!")

                    return averaged_csv_path
                else:
                    return list_of_runs[0] # Since there is only one just return the one

            ####################################################################################################
            ########## Start of main code
            ####################################################################################################

            start_time = time.time() # Profiling
           
            marker_list=["// >>>>> randomize_attack fuzz start",\
                            "// >>>>> randomize_attack fuzz end",\
                            "// >>>>> randomizing num of attack fuzz start 2",\
                            "// >>>>> randomizing num of attack fuzz end 2",\
                            "// >>>>> randomizing num of attack fuzz Te1 start 1",\
                            "// >>>>> randomizing num of attack fuzz Te1 end 1",\
                            "// >>>>> randomizing num of attack fuzz Te1 start 2",\
                            "// >>>>> randomizing num of attack fuzz Te1 end 2",\
                            "// >>>>> randomizing num of attack fuzz Te2 start 1",\
                            "// >>>>> randomizing num of attack fuzz Te2 end 1",\
                            "// >>>>> randomizing num of attack fuzz Te2 start 2",\
                            "// >>>>> randomizing num of attack fuzz Te2 end 2",\
                            "// >>>>> randomizing num of attack fuzz Te3 start 1",\
                            "// >>>>> randomizing num of attack fuzz Te3 end 1",\
                            "// >>>>> randomizing num of attack fuzz Te3 start 2",\
                            "// >>>>> randomizing num of attack fuzz Te3 end 2"]
            
            if self.attack_name == "Flush_Reload":
                CFileFuzzer.removeFuzzCodeBetweenMarkers(self.local_flush_reload_path, self.START_MARKER, self.END_MARKER)
                for i in range(0,len(marker_list),2):
                    # print("Marker\n")
                    # print(marker_list[i])
                    CFileFuzzer.removeFuzzCodeBetweenMarkers(self.local_flush_reload_path, marker_list[i], marker_list[i+1])
            else:
                CFileFuzzer.removeFuzzCodeBetweenMarkers(self.local_spectre_path, self.START_MARKER, self.END_MARKER)
            
            cff.scpAndCompileCode(extraPrints=False)
            
            pass

            # # Grab baseline data
            # retry_counter_1 = 0
            # while True:
            #     try:
            #         csv_of_no_fuzzing_perf = exec_perf()
            #         #csv_of_no_fuzzing_papi = exec_papi()
            #         break
            #     except pandas.errors.EmptyDataError as ede:
            #         retry_counter_1 += 1
            #         logger.error(f"Retry counter: {retry_counter_1}, error:\n{ede}")
            #         continue # Retry
            #     except paramiko.ChannelException as ce:
            #         retry_counter_1 += 1
            #         logger.error(f"Retry counter: {retry_counter_1}, error:\n{ce}")
            #         self.sshConnector.reset_connection()
            #         logger.warning("Resetted connection...")
            #         continue # Retry
                
            # pass

            # Add fuzzing
            

            fuzz(experiment_name, initial_value, increment) # To edit what fuzz, go to the declaration of fuzz()
            
            pass

            # Grab fuzzed spectre's HPCs
            retry_counter_2 = 0
            while True:
                try:
                    if (self.HPC_FRAMEWORK=="perf"):
                       csv_of_yes_fuzzing_perf = exec_perf()
                    elif (self.HPC_FRAMEWORK=="PAPI"):
                        csv_of_yes_fuzzing_papi = exec_papi()
                    else:
                        csv_of_yes_fuzzing_papi = exec_rapl()
                    break

                except pandas.errors.EmptyDataError as ede:
                    retry_counter_2 += 1
                    logger.error(f"Retry counter: {retry_counter_2}, error:\n{ede}")
                    continue # Retry
                except paramiko.ChannelException as ce:
                    retry_counter_1 += 1
                    logger.error(f"Retry counter: {retry_counter_1}, error:\n{ce}")
                    self.sshConnector.reset_connection()
                    logger.warning("Resetted connection...")
                    continue # Retry

            pass


        else:
            logger.error("SSH Connection failed.")

        pass
    
    
    
    def detectionResult(self,experiment_name):
        ## Checking Detection Model 
        test_file_name = f"{self.HPC_FRAMEWORK}_data_0.csv" #"PAPI_data_0.csv"     
        good_fuzz = "False"
        if self.model_name == "Model_1":
            D=DetectionModel_1(test_file_name, experiment_name, self.attack_name)
            ### SVM ###
            print("************************************************************************************************")
            print('************* ' + str(self.model_name) + ':SVM *************')
            prediction_svm=DetectionModel_1.svm_model(D)
            print(prediction_svm)
            detection_svm=DetectionModel_1.attack_code_detected(prediction_svm)

            ### MLP ###
            print('************* ' + str(self.model_name) + ':MLP *************')
            print("****************************************************************")
            prediction_mlp=DetectionModel_1.mlp_model(D)
            print(prediction_mlp)
            detection_mlp=DetectionModel_1.attack_code_detected(prediction_mlp)
            if detection_svm != 'Low' or detection_mlp != 'Low':
                print('The attack is detected by SVM with ' + str(detection_svm) + ' confidence')
                print('The attack is detected by MLP with ' + str(detection_mlp) + ' confidence')
                print("****************************************************************")
            else:
                print('The attack is not detected!!\n')
                print('!!!!!!!!!********Fuzzing Successfull**********!!!!!!!!')
                print("************************************************************************************************")
                good_fuzz = "True"
            
        if self.model_name == "Model_2":
            if self.attack_name=="spectreV1":            
                D=DetectionModel_2(test_file_name, experiment_name, self.attack_name)
                print("----------------NN--------------------------------")
                prediction_nn=DetectionModel_2.nn_model(D)
                print(prediction_nn)
                detection_outcome_nn=DetectionModel_2.attack_code_detected(prediction_nn)
            else:
                D=DetectionModel_2_spectre2(test_file_name, experiment_name, self.attack_name)
                print("----------------NN--------------------------------")
                prediction_nn=DetectionModel_2_spectre2.nn_model(D)
                print(prediction_nn)
                detection_outcome_nn=DetectionModel_2_spectre2.attack_code_detected(prediction_nn)

            if detection_outcome_nn != 'Low':
                print('The attack is detected with ' + str(detection_outcome_nn) + ' confidence')
            else:
                print('The attack is not detected!!\n')
                print('!!!!!!!!!Fuzzing Successfull!!!!!!!!') 
                good_fuzz = "True"

        if self.model_name == "Model_3":
            D=DetectionModel_3(test_file_name, experiment_name, self.attack_name)
            ### SVM ###
            print("----------------SVM--------------------------------")
            prediction_svm=DetectionModel_3.svm_model(D)
            print(prediction_svm)
            #print("Accuracy: ", accuracy)
            detection_outcome_svm=DetectionModel_3.attack_code_detected(prediction_svm)
 

            ### RF ###
            print("----------------RF-------------------------------")
            prediction_rf=DetectionModel_3.rf_model(D)
            print(prediction_rf)
            #print("Accuracy: ", accuracy)
            detection_outcome_rf=DetectionModel_3.attack_code_detected(prediction_rf)


            ### DT ###
            print("----------------DT--------------------------------")
            prediction_dt=DetectionModel_3.dt_model(D)
            print(prediction_dt)
            #print("Accuracy: ", accuracy)
            detection_outcome_dt=DetectionModel_3.attack_code_detected(prediction_dt)
            
            if detection_outcome_svm != 'Low' or detection_outcome_rf != 'Low' or detection_outcome_dt != 'Low':
                print('The attack is detected with ' + str(detection_outcome_svm) + ' confidence')
                print('The attack is detected with ' + str(detection_outcome_rf) + ' confidence')
                print('The attack is detected with ' + str(detection_outcome_dt) + ' confidence')
            else:
                print('The attack is not detected!!\n')
                print('!!!!!!!!!Fuzzing Successfull!!!!!!!!')        
                good_fuzz = "True"

        if self.model_name == "Model_4":
            if self.attack_name=="spectreV1":
                D=DetectionModel_4(test_file_name, experiment_name, self.attack_name)
                ### SVM ###
                print("----------------SVM--------------------------------")
                prediction_svm=DetectionModel_4.svm_model(D)
                print(prediction_svm)
                #print("Accuracy: ", accuracy)
                detection_outcome_svm=DetectionModel_4.attack_code_detected(prediction_svm)

                ### CNN ###
                print("----------------CNN--------------------------------")
                prediction_cnn=DetectionModel_4.cnn_model(D)
                print(prediction_cnn)
                #print("Accuracy: ", accuracy)
                detection_outcome_cnn=DetectionModel_4.attack_code_detected(prediction_cnn)
            else: 
                D=DetectionModel_4_spectre2(test_file_name, experiment_name, self.attack_name)
                ### SVM ###
                print("----------------SVM--------------------------------")
                prediction_svm=DetectionModel_4_spectre2.svm_model(D)
                print(prediction_svm)
                #print("Accuracy: ", accuracy)
                detection_outcome_svm=DetectionModel_4_spectre2.attack_code_detected(prediction_svm)

                ### CNN ###
                print("----------------CNN--------------------------------")
                prediction_cnn=DetectionModel_4_spectre2.cnn_model(D)
                print(prediction_cnn)
                #print("Accuracy: ", accuracy)
                detection_outcome_cnn=DetectionModel_4_spectre2.attack_code_detected(prediction_cnn)
   
            if detection_outcome_svm != 'Low'  or detection_outcome_cnn != 'Low':
                print('The attack is detected with ' + str(detection_outcome_svm) + ' confidence')
                # print('The attack is detected with ' + str(detection_outcome_lr) + ' confidence')
                # print('The attack is detected with ' + str(detection_outcome_lda) + ' confidence')
                print('The attack is detected with ' + str(detection_outcome_cnn) + ' confidence')
            else:
                print('The attack is not detected!!\n')
                print('!!!!!!!!!Fuzzing Successfull!!!!!!!!')        
                good_fuzz = "True" 

            # if detection_outcome != 'Low':
            #     print('The attack is detected with ' + str(detection_outcome_svm) + ' confidence')
            # else:
            #     print('The attack is not detected!!\n')
            #     print('!!!!!!!!!Fuzzing Successfull!!!!!!!!')
            #     good_fuzz = "True"

            # ### LR ###
            # print("----------------LR--------------------------------")
            # prediction_lr=DetectionModel_4.lr_model(D)
            # print(prediction_lr)
            # #print("Accuracy: ", accuracy)
            # detection_outcome_lr=DetectionModel_4.attack_code_detected(prediction_lr)
            # # if detection_outcome != 'Low':
            # #     print('The attack is detected with ' + str(detection_outcome) + ' confidence')
            # # else:
            # #     print('The attack is not detected!!\n')
            # #     print('!!!!!!!!!Fuzzing Successfull!!!!!!!!')
            # #     good_fuzz = "True"  

            # ### LDA ###
            # print("----------------LDA--------------------------------")
            # prediction_lda=DetectionModel_4.lda_model(D)
            # print(prediction_lda)
            # #print("Accuracy: ", accuracy)
            # detection_outcome_lda=DetectionModel_4.attack_code_detected(prediction_lda)
            # # if detection_outcome != 'Low':
            # #     print('The attack is detected with ' + str(detection_outcome) + ' confidence')
            # # else:
            # #     print('The attack is not detected!!\n')
            # #     print('!!!!!!!!!Fuzzing Successfull!!!!!!!!')
            # #     good_fuzz = "True"  





        if self.model_name == "Model_5":
                    D=DetectionModel_5(test_file_name, experiment_name, self.attack_name)
                    ### CNN ###
                    print("************************************************************************************************")
                    print('************* ' + str(self.model_name) + ':CNN *************')
                    prediction_cnn=DetectionModel_5.cnn_model(D)
                    print(prediction_cnn)
                    detection_cnn=DetectionModel_5.attack_code_detected(prediction_cnn)

                   
                    if detection_cnn != 'Low':
                        print('The attack is detected by SVM with ' + str(detection_cnn) + ' confidence')
                        print("****************************************************************")
                    else:
                        print('The attack is not detected!!\n')
                        print('!!!!!!!!!********Fuzzing Successfull**********!!!!!!!!')
                        print("************************************************************************************************")
                        good_fuzz = "True"







        # if good_fuzz == "False":
        if self.attack_name == "Flush_Reload":
            CFileFuzzer.removeFuzzCodeBetweenMarkers(self.local_flush_reload_path, self.START_MARKER, self.END_MARKER)
        else:
            CFileFuzzer.removeFuzzCodeBetweenMarkers(self.local_spectre_path, self.START_MARKER, self.END_MARKER)
        # CFileFuzzer.removeFuzzCodeBetweenMarkers(self.local_spectre_path, self.START_MARKER, self.END_MARKER)
        return good_fuzz
