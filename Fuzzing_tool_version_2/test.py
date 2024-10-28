import random
import logging
import sys

# Initialize logger
logger = logging.getLogger()

# Define the ranges for each experiment
experiment_ranges = {
    "cache_misses": (10000, 200000),
    "br_inst_retired": (5000, 50000),
    "br_misp_retired": (5000, 50000),
    "total_inst_retired": (10, 70),
    "randomize_attack": (0, 100)
}



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

        
        


selected_exp=["br_misp_retired", "cache_misses", "total_inst_retired"]   

initial_values = get_initial_values(selected_exp, experiment_ranges)

print(f"moduletest_{selected_exp[1]}.csv")
print(initial_values)