
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


if __name__ == "__main__":
## Test Setup info

    run_time=10
    # Get new time
    timenow = datetime.now()
    formatted_timenow = timenow.strftime("%Y_%m_%d_%H_%M_%S")

    # File_name for the final outcomes of every run-time
    outcome_file_name = f"outcome_{formatted_timenow}.txt"

    for m in range(0, run_time):
        print("******************************** Run Time # : "+str(m)+" ****************************************************************")
        config_file = "D:/CPR Research/Topic8. Adversarial_attack/myversion/Fuzzing_tool/framework.config"
        list_of_experiments=[ "cache_misses","total_inst_retired","br_inst_retired","br_misp_retired"] #"randomize_attack"]
        random.shuffle(list_of_experiments)
        #print(list_of_experiments)
        attempts=0
        fuzz_result="False"
        count=0
        experiment_name=""
        start_time = time.time()
        while fuzz_result == "False":
            experiment_name=list_of_experiments[count]
            # logger.info(f"Module Testing:  {experiment_name}")
            if experiment_name == "cache_misses":
                initial_value=10000
                increment=10000
                stop_point = 200000
            elif experiment_name == "br_inst_retired": 
                initial_value=5000
                increment=5000
                stop_point = 50000
            elif experiment_name == "br_misp_retired":
                initial_value=5000
                increment=5000
                stop_point = 50000
            elif experiment_name == "total_inst_retired":
                initial_value = 10
                increment = 10
                stop_point = 70

            elif experiment_name == "randomize_attack":
                initial_value = 100
                increment = -10
                stop_point = 0

            else:
                logger.error("Error in choosing correct fuzzing module")

            module=ModuleTester(config_file)

            # if module.attack_name=="Flush_Reload":
            #     experiment_name="randomize_attack"
            #     initial_value = 100
            #     increment = -10
            #     stop_point = 0

            for i in range(initial_value, stop_point,increment):
                logger.info(f"Module Testing: {experiment_name} | Parameter: {i} | Attempts: {attempts}")
                module.fuzz_Module(i,increment,experiment_name)
                fuzz_result=module.detectionResult(experiment_name)
                attempts = attempts + 1
                if fuzz_result == "True":
                    break
            count = count + 1
            if count >= len(list_of_experiments):
                   break

        if fuzz_result == "True":
            end_time = time.time()
            print("\n\n************************************************************************************************")
            print("*********Fuzzing Completed************\n")
            print(f"Selected Module that works: {experiment_name} | Parameter: {i}")
            print(f"Number of attempts: {attempts}")
            print(f"Time spent: {(end_time - start_time):.2f}s")
            print("****************************************************************")


            # Save the result
            outcome = [["Run Time #: ", m],["Selected Module that works: ", experiment_name],\
                        ["Parameter: ", i], ["Number of attempts: ", attempts],\
                            ["Time spent: ", (end_time - start_time)]]
            
            # Open the file in append mode ('a')
            with open(f"{module.local_collecteddata_folder}/Result_fuzzing_tool/{outcome_file_name}", 'a', newline='') as file:
                writer = csv.writer(file)
                # Append the data
                for row in outcome:
                    writer.writerow(row)
            
            # Save the last spectre output           
            source_path=f"{module.local_collecteddata_folder}/{module.filename_prefix}/{experiment_name}/attack_output/{module.filename_prefix}_{experiment_name}_attack_output_0.txt"
            destination_path = f"{module.local_collecteddata_folder}/Result_fuzzing_tool/{outcome_file_name}"

            # Read from source and append to destination
            try:
                with open(source_path, mode='r', newline='') as file:
                    reader = csv.reader(file)
                    with open(destination_path, mode='a', newline='') as dest_file:
                        writer = csv.writer(dest_file)
                        for row in reader:
                            writer.writerow(row)
                logger.info("Data appended successfully.")
            except FileNotFoundError:
                logger.error("The source/destination file does not exist.")
        else:
            logger.error("Fuzzing tool could not find an effective module")

    






