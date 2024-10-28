
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
import random
import shutil
# Project imports
from module_tester import ModuleTester


# Function to get initial value based on experiment name
def get_initial_values(experiment_names, experiment_ranges):
    initial_values=[]
    for i in range(0, len(experiment_names)):
        if (experiment_names[i] in experiment_ranges != False):     
            start_point, stop_point = experiment_ranges[experiment_names[i]]
            # Ensure the correct order of start and stop values for randint
            initial_values.append(random.randint(start_point, stop_point))
        else:
            logger.error("Error in choosing correct fuzzing module")
            sys.exit(1)  # Exit the program if an error is encountered
            
    return initial_values


# Read from source and append to destination
def append_data_to_file(destination_path, content):
    with open(destination_path, mode='a', newline='') as dest_file:
        writer = csv.writer(dest_file)
        for row in content:
            writer.writerow(row)




if __name__ == "__main__":
    ## Test Setup info

    run_time=2
    # Get new time
    timenow = datetime.now()
    formatted_timenow = timenow.strftime("%Y_%m_%d_%H_%M_%S")

    # File_name for the final outcomes of every run-time
    outcome_file_name = f"outcome_{formatted_timenow}.txt"

    # File_name for listing all the results of every run-time
    output_file_name = f"output_{formatted_timenow}.txt"

    for m in range(1, run_time+1):
        print("******************************** Run Time # : "+str(m)+" ****************************************************************")
        config_file = "D:/CPR Research/Topic8. Adversarial_attack/FinalWorkDir/Random_fuzzing/framework.config"

        # Define the list of modules/experiments
        list_of_experiments=[ "cache_misses","total_inst_retired","br_inst_retired","br_misp_retired"] # , "randomize_attack"]

        # Define the ranges for each experiment
        experiment_ranges = {
            "cache_misses": (10000, 200000),
            "br_inst_retired": (5000, 50000),
            "br_misp_retired": (5000, 50000),
            "total_inst_retired": (10, 70),
            "randomize_attack": (0, 100)
        }

        attempts=1
        fuzz_result="False"
        start_time = time.time()

        while fuzz_result == "False":
            module=ModuleTester(config_file)
            if module.attack_name=="Flush_Reload":
                experiment_names=["randomize_attack"]
                initial_values = get_initial_values(experiment_names, experiment_ranges) 
            else:
            # Randomly select more than 1 element from the list
                experiment_names = random.sample(list_of_experiments, random.randint(2, len(list_of_experiments)))
                initial_values = get_initial_values(experiment_names, experiment_ranges)       
            

            logger.info(f"Run Time: {m} | Module Testing: {experiment_names} | Parameter: {initial_values} | Attempts: {attempts}")
            module.fuzz_Module(initial_values,experiment_names)       
            fuzz_result=module.detectionResult()

            # Save the result
            destination_path_outcome = f"{module.local_collecteddata_folder}/Result_fuzzing_tool/{outcome_file_name}"
            destination_path_output = f"{module.local_collecteddata_folder}/Result_fuzzing_tool/{output_file_name}"
            output = [[f"Run Time: {m} | Module Testing: {experiment_names} | Parameter: {initial_values} | Attempts: {attempts}"]]
            
            # Open the file in append mode ('a') and write it
            append_data_to_file(destination_path_output, output)


            if fuzz_result == "True":
                end_time = time.time()
                print("\n************************************************************************************************")
                print("*********Fuzzing Completed************\n")
                print(f"Selected Module that works: {experiment_names} | Parameter: {initial_values}")
                print(f"Total Attempts: {attempts}")
                print(f"Time spent: {(end_time - start_time):.2f}s")
                print("****************************************************************")


                # Save the result
                output = [["Fuzzing successful!!"],["-------------------------------------------"]]
                outcome = [["Run time #: ", m],["***************************************"],["Selected Modules that works: ", experiment_names],\
                            ["Parameters: ", initial_values], ["Attempts: ", attempts],\
                                ["Time spent: ", (end_time - start_time)]]
                
                # Open the file in append mode ('a')
                append_data_to_file(destination_path_outcome, outcome)
                append_data_to_file(destination_path_output, output)
                
                # Save the last spectre output           
                source_path=f"{module.local_collecteddata_folder}/{module.filename_prefix}/attack_output/{module.filename_prefix}_attack_output_0.txt"

                try:
                    with open(source_path, mode='r', newline='') as file:
                        reader = csv.reader(file)
                        append_data_to_file(destination_path_outcome, reader)
                    logger.info("Data appended successfully.")
                except FileNotFoundError:
                    logger.error("The source/destination file does not exist.")
            
                break
            attempts = attempts + 1

        # else:
        #     logger.error("Fuzzing tool could not find an effective module")
        #     outcome = [["Fuzzing tool could not find an effective module "]]
        #      # Open the file in append mode ('a')
        #     with open(f"{module.local_collecteddata_folder}/Result_fuzzing_tool/{outcome_file_name}", 'a', newline='') as file:
        #         writer = csv.writer(file)
        #         # Append the data
        #         for row in outcome:
        #             writer.writerow(row)

    






