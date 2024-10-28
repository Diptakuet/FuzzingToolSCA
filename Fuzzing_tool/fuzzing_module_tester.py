###############################################################################################
#  
#  Created by: Jonathan Tan (jona1115@iastate.edu)
#  
###########################################################################################
#  
#  fuzzing_module_tester.py:
#  For testing all modules in CFileFuzzer.py.
#  
#  MODIFICATION HISTORY:
# 
#  Ver          Who       Date	      Changes
#  -----        --------- ---------- ----------------------------------------------
#  1.00	        Jonathan  5/9/2024   Created file.
#  myversion    Debopriya 5/15/2024  Added Dectection Models + modules 
###############################################################################################

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
from Tested_Detection_models.Model_2.spectreV1.detection_model_2 import DetectionModel_2
from Tested_Detection_models.Model_3.Flush_Reload.detection_model_3 import DetectionModel_3
from Tested_Detection_models.Model_4.spectreV1.detection_model_4 import DetectionModel_4
from Tested_Detection_models.Model_4.spectreV2.detection_model_4 import DetectionModel_4

ssh_host = '10.26.53.120'
ssh_username = 'mais_lab'
ssh_password = 'berk5416'

filename_prefix = "moduletest" # eg. {filename_prefix}_xxx.txt

######################################################################################################################
# Change based on attack/Model
######################################################################################################################
model_name = "Model_2"
attack_name ="spectreV1" #"Flush_Reload"  # spectreV2
########################################################################################################################
########################################################################################################################


if attack_name=="spectreV1":
    target_attack = 0
elif attack_name=="spectreV2":
    target_attack = 1
else:
    target_attack=""


if __name__ == "__main__":
    """
    The idea is that we want to collect all HPCs that this framework uses, so when we fuzz,
    we can see the changes of all counters.

    For perf's list, we will run: sudo perf stat -e cache-misses,cache-references,br_inst_retired.all_branches,br_misp_retired.all_branches,mem-loads,inst_retired.any,cpu_clk_unhalted.ref_tsc,cpu_clk_unhalted.ref_xclk_any,bus-cycles -I 100
    For PAPI's list, we will run: ~/jonathan_project/spectre
    -V1_model2/data_collect.sh
                                  (note: the events are set in events.conf in that dir)
                        
    To make sure all profiling tools are running the same spectre code, we will use the spectre
    code in "fuzzing_module_tester/spectre/"
    """
    sshConnector = SshConnector(ssh_host, ssh_username, ssh_password)
    sshConnector.connect()

#######################################################################################################################
# Change based on attack/Model
#######################################################################################################################
    # Markers (fyi markers are used to tell the framework where in the c code to add instructions)
    START_MARKER = "// >>>>> cache_misses fuzz start"
    END_MARKER = "// >>>>> cache_misses fuzz end"

    #perf_HPCs = "cache-misses,cache-references,br_inst_retired.all_branches,br_misp_retired.all_branches,mem-loads,inst_retired.any,cpu_clk_unhalted.ref_tsc,cpu_clk_unhalted.ref_xclk_any,bus-cycles" # Edit this to whatever counters you want to collect and it *should* just work
    perf_HPCs = "br_inst_retired.all_branches,br_misp_retired.all_branches,cache-misses,cache-references" 
    HPC_COLLECT_FREQ_MS = 100
    perf_run_time_s = 40
    increment_len = 4000


    #papi_events= ["PAPI_L3_TCA", "PAPI_L3_TCM", "PAPI_BR_INS", "PAPI_BR_MSP", "PAPI_TOT_INS"]
    #papi_events = ["PAPI_TOT_CYC", "PAPI_L1_DCM", "PAPI_L3_TCM", "PAPI_L3_TCA"]
    papi_events = ["PAPI_L3_TCA", "PAPI_L3_TCM", "PAPI_TOT_INS"]
########################################################################################################################
########################################################################################################################


    # File/Folder Paths
    server_collecteddata_folder = f"/home/mais_lab/victim_side/{model_name}/Data"
    server_attack_folder = f"/home/mais_lab/victim_side/{model_name}/fuzzing_module_tester/{attack_name}"
    local_collecteddata_folder = f"D:/CPR Research/Topic8. Adversarial_attack/myversion/Fuzzing_tool/Tested_Detection_models/{model_name}/{attack_name}/Test_Data"
    local_perf_txt_path = ""        # Initialized in exec_perf()
    local_spectre_txt_path = ""     # Initialized in exec_perf()
    local_perf_csv_path = ""        # Initialized in exec_perf()
    server_data_collect_sh_folder = f"/home/mais_lab/victim_side/{model_name}/fuzzing_module_tester"
    server_data_collect_sh_collecteddata_folder = f"/home/mais_lab/victim_side/{model_name}/fuzzing_module_tester/collecteddata"

    
    local_PAPI_out_csv_path = ""    # Initialized in exec_papi()
    local_spectre_path = f"D:/CPR Research/Topic8. Adversarial_attack/myversion/Fuzzing_tool/targeted_attacks/{attack_name}/spectre.c"
    local_flush_reload_path = f"D:/CPR Research/Topic8. Adversarial_attack/myversion/Fuzzing_tool/targeted_attacks/{attack_name}/newspy.cpp"


    # Common settings
    AVERAGE_COUNT = 5 # Set to 1 if no need average

    # Final names and stuff of the results file
    experiment_description = ""
    experiment_name = ""


########################################################################################################################
# Change based on attack/Model
########################################################################################################################
    # Create CFileFuzzer object for fuzzing.
    cff = CFileFuzzer(sshConnector, local_spectre_path, server_attack_folder)
    #cff = CFileFuzzer(sshConnector, local_flush_reload_path, server_attack_folder)
#########################################################################################################################
#########################################################################################################################
   
    
    if sshConnector.getSshConnectionStatus() is True:
        def fuzz():
            """
            This function is to do what the framework is supposed to do: Add fuzzing instructions
            and scp the modified spectre to the server and compile it, so that the "exec_" functions
            can execute it and profile it.
            """
            cff.insertProfilingStuff()

            ##################################################################
            ##### User zone: Add vars and call the fuzzing functions here...
            ##### Fuzzing functions can be found in CFileFuzzer.py
            ##################################################################
            # Description
            global experiment_description, experiment_name
            
            experiment_name = "cache_misses"
            #experiment_name = "randomize_attack" # This will become file names so don't put illegal symbols
            #experiment_name = "total_instruction" # This will become file names so don't put illegal symbols
            #experiment_name = "br_inst_retired" # This will become file names so don't put illegal symbols
            #experiment_name = "br_misp_retired" # This will become file names so don't put illegal symbols
            
            experiment_description = f"This is testing the {experiment_name} module with increment {increment_len}"
            # Pick your module here:

            if experiment_name == "cache_misses":
                cff.setInitialLENForCacheMisses(0)
                cff.increaseCacheMisses(increment_len, extraPrints=False)

            if experiment_name == "br_inst_retired":
                cff.increaseBranchInstRetiredAllBranches(0,extraPrints=False)
            
            if experiment_name == "br_misp_retired":
                cff.impactBranchMissPredictRetired(0,extraPrints=False)

            if experiment_name == "total_instruction":
                cff.decreaseTotalInstrCompleted(60,extraPrints=False)

            if experiment_name == "randomize_attack":
                cff.randomizingAttackPerEncryption(70,extraPrints=False)


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
                formatted_timenow = timenow.strftime("%Y_%m%d_%H%M_%S")
                
                perf_command = f"perf stat -a -e {perf_HPCs} -I {HPC_COLLECT_FREQ_MS}"

                # Run perf and output it to a temp file
                perf_output_temp_file = f"~perf_data_{i}.txt"
                perf_output_temp_path = f"{server_collecteddata_folder}/{perf_output_temp_file}"
                sshConnector.execute_sudo_command_nonblocking_nonlive(f"{perf_command} 2> {perf_output_temp_path}", ssh_password, timeout=perf_run_time_s)
                
                # Wait a bit so perf started
                time.sleep(1)

                # Run spectre
                spectre_output_temp_file = f"~{filename_prefix}_{experiment_name}_attack_output_{i}.txt"
                spectre_output_temp_path = f"{server_collecteddata_folder}/{spectre_output_temp_file}"
                sshConnector.execute_command(f"(cd {server_attack_folder} && ./spectre > {spectre_output_temp_path})", wantPrint=False)

                # I believe when execute_command ends, it also kills perf, so if the code is here you 
                # can expect that perf has captured spectre's effect on the HPC


                perf_output_local_folder = f"{local_collecteddata_folder}/{filename_prefix}/{experiment_name}"

                # Check if the new file already exists
                if os.path.exists(f"{perf_output_local_folder}/{perf_output_temp_file}"):
                    os.remove(f"{perf_output_local_folder}/{perf_output_temp_file}")  # Remove it if it exists


                # Copy this temp files over
                sshConnector.scp_get(perf_output_temp_path, perf_output_local_folder)
                
                
                attack_output_local_folder = f"{local_collecteddata_folder}/{filename_prefix}/{experiment_name}/attack_output"
                # Check if the new file already exists
                if os.path.exists(f"{attack_output_local_folder}/{spectre_output_temp_file}"):
                    os.remove(f"{attack_output_local_folder}/{spectre_output_temp_file}")  # Remove it if it exists
 
                # Copy this temp files over
                sshConnector.scp_get(spectre_output_temp_path, attack_output_local_folder)

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
                sshConnector.execute_command(f"rm {perf_output_temp_path} && rm {spectre_output_temp_path}")


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
                averaged_csv_path = f"{local_collecteddata_folder}/{filename_prefix}/{experiment_name}/avged_perf_out_{i}.csv"
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
                
                
                data_collect_sh_out_temp_file = f"{filename_prefix}_{experiment_name}_output_{i}.txt"
                data_collect_sh_exec = f"./data_collect.sh {target_attack} > collecteddata/{data_collect_sh_out_temp_file}"
                sshConnector.execute_command(f"(cd {server_data_collect_sh_folder} && {data_collect_sh_exec})")

                # Scp the output back (unlike my idea in exec_perf(), I realized the use of temp files are not the best idea so that wont happen again)
                PAPI_Output_text = f"{server_data_collect_sh_collecteddata_folder}/PAPI_data.txt"
                PAPI_output_local_folder = f"{local_collecteddata_folder}/{filename_prefix}/{experiment_name}"
                if os.path.exists(f"{PAPI_output_local_folder}/PAPI_data.txt"):
                   os.remove(f"{PAPI_output_local_folder}/PAPI_data.txt")
                sshConnector.scp_get(PAPI_Output_text, PAPI_output_local_folder)
                old_name = f"{PAPI_output_local_folder}/PAPI_data.txt"
                new_name = f"{PAPI_output_local_folder}/PAPI_data_{i}.csv"
                # Check if the new file already exists
                if os.path.exists(new_name):
                    os.remove(new_name)  # Remove it if it exists
                os.rename(old_name, new_name)
                local_PAPI_out_csv_path = new_name
                server_data_collect_sh_output = f"{server_data_collect_sh_collecteddata_folder}/{data_collect_sh_out_temp_file}"
                attack_output_local_folder = f"{local_collecteddata_folder}/{filename_prefix}/{experiment_name}/attack_output"
                sshConnector.scp_get(server_data_collect_sh_output, attack_output_local_folder)

                # Parse PAPI's output
                add_CSV_header.add_csv_header(local_PAPI_out_csv_path, local_PAPI_out_csv_path, papi_events)
                                            #[
                                            #                                 "PAPI_L3_TCA",
                                            #                                 "PAPI_L3_TCM",
                                            #                                 "PAPI_BR_INS",
                                            #                                 "PAPI_BR_MSP",
                                            #                                 "PAPI_TOT_INS",
                                            #                             ])

                # Sometimes for some reason PAPI wont return anything, probably due to failing to latch to a PID
                # So, here we check that if there is only 1 line in the csv, rerun:
                line_count = 0
                with open(local_PAPI_out_csv_path, 'r', newline='') as csvfile:
                    reader = csv.reader(csvfile)
                    line_count = sum(1 for _ in reader)
                if (line_count < 10):
                    i -= 1
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
                averaged_csv_path = f"{local_collecteddata_folder}/{filename_prefix}/{experiment_name}/avged_PAPI_data.csv"
                csva = CSVAverager(list_of_runs, averaged_csv_path)
                logger.debug("PAPI averaged!")

                return averaged_csv_path
            else:
                return list_of_runs[0] # Since there is only one just return the one

        def exec_pcm(): # Did this so I can collapse the whole thing
            """
            IMPORTANT: This function is freshly copied from perf, it is NOT the pcm function you will need to edit it.
            
            This function run PCM AVERAGE_COUNT times, and average the results into a file.
            This function just run the attack code and the profiling tool, it doesn't compile the
            code or anything.

            @return file name of the averaged results
            """
            #    _______    ______   __       __ 
            #   /       \  /      \ /  \     /  |
            #   $$$$$$$  |/$$$$$$  |$$  \   /$$ |
            #   $$ |__$$ |$$ |  $$/ $$$  \ /$$$ |
            #   $$    $$/ $$ |      $$$$  /$$$$ |
            #   $$$$$$$/  $$ |   __ $$ $$ $$/$$ |
            #   $$ |      $$ \__/  |$$ |$$$/ $$ |
            #   $$ |      $$    $$/ $$ | $/  $$ |
            #   $$/        $$$$$$/  $$/      $$/ 
            #                                    
            # Lets start by collecting perf data
            
            list_of_runs = []
            
            for i in range(0, AVERAGE_COUNT):
                # Get time
                timenow = datetime.now()
                formatted_timenow = timenow.strftime("%Y_%m%d_%H%M_%S")
                
                perf_command = f"perf stat -e {perf_HPCs} -I {HPC_COLLECT_FREQ_MS}"

                # Run perf and output it to a temp file
                perf_output_temp_file = f"~{filename_prefix}_{formatted_timenow}.txt"
                perf_output_temp_path = f"{server_collecteddata_folder}/{perf_output_temp_file}"
                sshConnector.execute_sudo_command_nonblocking_nonlive(f"{perf_command} 2> {perf_output_temp_path}", ssh_password, timeout=perf_run_time_s)
                
                # Wait a bit so perf started
                time.sleep(1)

                # Run spectre
                spectre_output_temp_file = f"~{filename_prefix}_{formatted_timenow}_spectre_output.txt"
                spectre_output_temp_path = f"{server_collecteddata_folder}/{spectre_output_temp_file}"
                sshConnector.execute_command(f"(cd {server_attack_folder} && ./spectre > {spectre_output_temp_path})", wantPrint=False)

                # I believe when execute_command ends, it also kills perf, so if the code is here you 
                # can expect that perf has captured spectre's effect on the HPC

                # Copy this temp files over
                sshConnector.scp_get(perf_output_temp_path, local_collecteddata_folder)
                sshConnector.scp_get(spectre_output_temp_path, local_collecteddata_folder)

                # Rename perf's output file
                old_name = f"{local_collecteddata_folder}/{perf_output_temp_file}"
                old_name_split = old_name.split('~')    # Remove the ~ at the beginning of the file
                new_name = "".join(old_name_split)      # Remove the ~ at the beginning of the file
                os.rename(old_name, new_name)
                local_perf_txt_path = new_name

                # Rename spectre's output file
                old_name = f"{local_collecteddata_folder}/{spectre_output_temp_file}"
                old_name_split = old_name.split('~')    # Remove the ~ at the beginning of the file
                new_name = "".join(old_name_split)      # Remove the ~ at the beginning of the file
                os.rename(old_name, new_name)
                local_spectre_txt_path = new_name

                # Delete perf and spectre temp files in the server
                sshConnector.execute_command(f"rm {perf_output_temp_path} && rm {spectre_output_temp_path}")

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
                averaged_csv_path = f"{local_collecteddata_folder}/{filename_prefix}_avged_{formatted_timenow}_perf_out.csv"
                csva = CSVAverager(list_of_runs, averaged_csv_path)
                logger.debug("Perf averaged!")

                return averaged_csv_path
            else:
                return list_of_runs[0] # Since there is only one just return the one


        ####################################################################################################
        ########## Start of main code
        ####################################################################################################

        start_time = time.time() # Profiling



######################################################################################
# Change based on attack/model
######################################################################################
        # Remove fuzzing so we get to get the baseline data of the "clean" spectre code
        #CFileFuzzer.removeFuzzCodeBetweenMarkers(local_flush_reload_path, START_MARKER, END_MARKER)
        CFileFuzzer.removeFuzzCodeBetweenMarkers(local_spectre_path, START_MARKER, END_MARKER)
        
        
        marker_list=["// >>>>> randomizing num of attack fuzz start 1",\
                        "// >>>>> randomizing num of attack fuzz end 1",\
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
        
        if attack_name == "Flush-Reload":
            for i in range(0,len(marker_list),2):
                print(marker_list[i])
                CFileFuzzer.removeFuzzCodeBetweenMarkers(local_flush_reload_path, marker_list[i], marker_list[i+1])
        
        
        cff.scpAndCompileCode(extraPrints=False)
        
        pass

        # Grab baseline data
        retry_counter_1 = 0
        while True:
            try:
                #csv_of_no_fuzzing_perf = exec_perf()
                csv_of_no_fuzzing_papi = exec_papi()
                break
            except pandas.errors.EmptyDataError as ede:
                retry_counter_1 += 1
                logger.error(f"Retry counter: {retry_counter_1}, error:\n{ede}")
                continue # Retry
            except paramiko.ChannelException as ce:
                retry_counter_1 += 1
                logger.error(f"Retry counter: {retry_counter_1}, error:\n{ce}")
                sshConnector.reset_connection()
                logger.warning("Resetted connection...")
                continue # Retry
            
        pass

        # Add fuzzing
        fuzz() # To edit what fuzz, go to the declaration of fuzz()
        
        pass

        # Grab fuzzed spectre's HPCs
        retry_counter_2 = 0
        while True:
            try:
                #csv_of_yes_fuzzing_perf = exec_perf()
                csv_of_yes_fuzzing_papi = exec_papi()
                break
            except pandas.errors.EmptyDataError as ede:
                retry_counter_2 += 1
                logger.error(f"Retry counter: {retry_counter_2}, error:\n{ede}")
                continue # Retry
            except paramiko.ChannelException as ce:
                retry_counter_1 += 1
                logger.error(f"Retry counter: {retry_counter_1}, error:\n{ce}")
                sshConnector.reset_connection()
                logger.warning("Resetted connection...")
                continue # Retry

        pass

        # Compare
        INF = 10000 # If the higher number in the range is greater than the number of rows, it will just stop at the last row, so this number is to tell it to stop at the last row
        # perf_no_fuzz_excel_row_range = (2, INF)
        # perf_yes_fuzz_excel_row_range = (31, INF)
        # perf_diff_dict = CSVComparer.compare_csv_files(csv_of_no_fuzzing_perf, 
        #                                                csv_of_yes_fuzzing_perf,
        #                                                perf_no_fuzz_excel_row_range,
        #                                                perf_yes_fuzz_excel_row_range)
        papi_no_fuzz_excel_row_range = (7, INF)
        papi_yes_fuzz_excel_row_range = (7, INF)
        papi_diff_dict = CSVComparer.compare_csv_files(csv_of_no_fuzzing_papi, 
                                                       csv_of_yes_fuzzing_papi,
                                                       papi_no_fuzz_excel_row_range,
                                                       papi_yes_fuzz_excel_row_range)

        # Write results to Excel
        # Get time
        timenow = datetime.now()
        formatted_timenow = timenow.strftime("%Y_%m%d_%H%M_%S")
        output_excel_file_path = f"{local_collecteddata_folder}/Final_result/RESULTS_{experiment_name}_{increment_len}.xlsx"
        # ExcelCreaterFromDict.create_excel_from_dicts_with_titles([perf_diff_dict,papi_diff_dict],
        #                                                          ["Perf Delta S.W. (%)", "PAPI Delta (%)"],
        #                                                          output_excel_file_path)

        # ExcelCreaterFromDict.create_excel_from_dicts_with_titles([perf_diff_dict],
        #                                                          ["perf Delta S.W. (%)"],
        #                                                          output_excel_file_path) 



        ExcelCreaterFromDict.create_excel_from_dicts_with_titles([papi_diff_dict],
                                                                 ["PAPI Delta (%)"],
                                                                 output_excel_file_path)                                            

        # Add notes:
        ExcelCreaterFromDict.prepend_row_with_text(output_excel_file_path,
                                                   [experiment_description],
                                                   [])

        logger.success(f"The results are in the Excel file: {output_excel_file_path}")

        # logger.info("System will open file now...")
        # subprocess.call(['open', output_excel_file_path])

        end_time = time.time()
        logger.info(f"Time spent\t\t\t: {(end_time - start_time):.2f}s")

        pass

    else:
        logger.error("SSH Connection failed.")
    
    pass
    


    
    ## Checking Detection Model
    #experiment_name = "" # This will become file names so don't put illegal symbols
    experiment_name = "cache_misses" # This will become file names so don't put illegal symbols
    #experiment_name = "br_inst_retired" # This will become file names so don't put illegal symbols
    #experiment_name = "br_misp_retired" # This will become file names so don't put illegal symbols
    #experiment_name = "total_instruction"
    #experiment_name = "randomize_attack"   
    test_file_name = "PAPI_data_0.csv" #"PAPI_data_0.csv"     

    if model_name == "Model_1":
        D=DetectionModel_1(test_file_name, experiment_name, attack_name)
        ### SVM ###
        print("----------------SVM--------------------------------")
        prediction_svm=DetectionModel_1.svm_model(D)
        print(prediction_svm)
        detection_outcome=DetectionModel_1.attack_code_detected(prediction_svm)
        if detection_outcome != 'Low':
            print('The attack is detected with ' + str(detection_outcome) + ' confidence')
        else:
            print('The attack is not detected!!\n')
            print('!!!!!!!!!Fuzzing Successfull!!!!!!!!')


       ### LR ###
        print("----------------LR--------------------------------")
        prediction_lr=DetectionModel_1.lr_model(D)
        print(prediction_lr)
        detection_outcome=DetectionModel_1.attack_code_detected(prediction_lr)
        if detection_outcome != 'Low':
            print('The attack is detected with ' + str(detection_outcome) + ' confidence')
        else:
            print('The attack is not detected!!\n')
            print('!!!!!!!!!Fuzzing Successfull!!!!!!!!')


       ### MLP ###
        print("----------------MLP--------------------------------")
        prediction_mlp=DetectionModel_1.mlp_model(D)
        print(prediction_mlp)
        detection_outcome=DetectionModel_1.attack_code_detected(prediction_mlp)
        if detection_outcome != 'Low':
            print('The attack is detected with ' + str(detection_outcome) + ' confidence')
        else:
            print('The attack is not detected!!\n')
            print('!!!!!!!!!Fuzzing Successfull!!!!!!!!')
        
    if model_name == "Model_2":
        D=DetectionModel_2(test_file_name, experiment_name, attack_name)
        #####  NN  #######
        prediction_nn=DetectionModel_2.nn_model(D)
        detection_outcome=DetectionModel_2.attack_code_detected(prediction_nn)
        if detection_outcome != 'Low':
            print('The attack is detected with ' + str(detection_outcome) + ' confidence')
        else:
            print('The attack is not detected!!\n')
            print('!!!!!!!!!Fuzzing Successfull!!!!!!!!')       

    if model_name == "Model_3":
        D=DetectionModel_3(test_file_name, experiment_name, attack_name)
        ### SVM ###
        print("----------------SVM--------------------------------")
        prediction_svm=DetectionModel_3.svm_model(D)
        print(prediction_svm)
        #print("Accuracy: ", accuracy)
        detection_outcome=DetectionModel_3.attack_code_detected(prediction_svm)
        if detection_outcome != 'Low':
            print('The attack is detected with ' + str(detection_outcome) + ' confidence')
        else:
            print('The attack is not detected!!\n')
            print('!!!!!!!!!Fuzzing Successfull!!!!!!!!')

       ### RF ###
        print("----------------RF--------------------------------")
        prediction_rf=DetectionModel_3.rf_model(D)
        print(prediction_rf)
        #print("Accuracy: ", accuracy)
        detection_outcome=DetectionModel_3.attack_code_detected(prediction_rf)
        if detection_outcome != 'Low':
            print('The attack is detected with ' + str(detection_outcome) + ' confidence')
        else:
            print('The attack is not detected!!\n')
            print('!!!!!!!!!Fuzzing Successfull!!!!!!!!')

       ### DT ###
        print("----------------DT--------------------------------")
        prediction_dt=DetectionModel_3.dt_model(D)
        print(prediction_dt)
        #print("Accuracy: ", accuracy)
        detection_outcome=DetectionModel_3.attack_code_detected(prediction_dt)
        if detection_outcome != 'Low':
            print('The attack is detected with ' + str(detection_outcome) + ' confidence')
        else:
            print('The attack is not detected!!\n')
            print('!!!!!!!!!Fuzzing Successfull!!!!!!!!')  

    if model_name == "Model_4":
        D=DetectionModel_4(test_file_name, experiment_name, attack_name)
        ### SVM ###
        print("----------------SVM--------------------------------")
        prediction_svm=DetectionModel_4.svm_model(D)
        print(prediction_svm)
        #print("Accuracy: ", accuracy)
        detection_outcome=DetectionModel_4.attack_code_detected(prediction_svm)
        if detection_outcome != 'Low':
            print('The attack is detected with ' + str(detection_outcome) + ' confidence')
        else:
            print('The attack is not detected!!\n')
            print('!!!!!!!!!Fuzzing Successfull!!!!!!!!')


       ### LR ###
        print("----------------LR--------------------------------")
        prediction_lr=DetectionModel_4.lr_model(D)
        print(prediction_lr)
        #print("Accuracy: ", accuracy)
        detection_outcome=DetectionModel_4.attack_code_detected(prediction_lr)
        if detection_outcome != 'Low':
            print('The attack is detected with ' + str(detection_outcome) + ' confidence')
        else:
            print('The attack is not detected!!\n')
            print('!!!!!!!!!Fuzzing Successfull!!!!!!!!')

       ### LDA ###
        print("----------------LDA--------------------------------")
        prediction_lda=DetectionModel_4.lda_model(D)
        print(prediction_lda)
        #print("Accuracy: ", accuracy)
        detection_outcome=DetectionModel_4.attack_code_detected(prediction_lda)
        if detection_outcome != 'Low':
            print('The attack is detected with ' + str(detection_outcome) + ' confidence')
        else:
            print('The attack is not detected!!\n')
            print('!!!!!!!!!Fuzzing Successfull!!!!!!!!')

       ### CNN ###
        print("----------------CNN--------------------------------")
        prediction_cnn=DetectionModel_4.cnn_model(D)
        print(prediction_cnn)
        #print("Accuracy: ", accuracy)
        detection_outcome=DetectionModel_4.attack_code_detected(prediction_cnn)
        if detection_outcome != 'Low':
            print('The attack is detected with ' + str(detection_outcome) + ' confidence')
        else:
            print('The attack is not detected!!\n')
            print('!!!!!!!!!Fuzzing Successfull!!!!!!!!')        
    
