###############################################################################################
#  
#  Created by: Jonathan Tan (jona1115@iastate.edu)
#  Date      : 3/4/2024
#  
###########################################################################################
#  
#  utils.py: Any utility functions not worthy of having its own class will go in here.
#  
#  Revision 1 (x/x/xxxx):
#  
###############################################################################################

# Library imports
import time
from loguru import logger
from datetime import datetime
import os
import numpy as np

# Project imports

# from main import ssh_host
# from main import ssh_username
# from main import ssh_password

# Start of code:
def attack_code_detected(detection_results_nparr, window_width=10, acceptable_high_threshold=0.9, acceptable_mid_threshold=0.5):
    """
    This function takes in a np array, and an int of the width of a running window, and
    two floats with the acceptable thresholds. If the window's average is greater than or
    equal to the acceptable_high_threshold, it returns "High". If it's less than the
    acceptable_high_threshold but greater than or equal to the acceptable_mid_threshold,
    it returns "Mid". Otherwise, it returns "Low".

    This method/function is partially written by, or written with the aid of, ChatGPT.
    """
    # Iterate through the array with a window of window_width elements

    toReturn = "Low" # Default to "Low"
    
    for i in range(len(detection_results_nparr) - (window_width - 1)):
        # Calculate the average of the current window
        window_average = np.mean(detection_results_nparr[i:i + window_width])
        # Check if the average is greater than or equal to the high threshold
        if window_average >= acceptable_high_threshold:
            toReturn = "High"
        # Check if the average is between the high threshold and the mid threshold
        elif window_average >= acceptable_mid_threshold:
            if (toReturn != "High"): toReturn = "Mid"               # We only want to highest rating

    # If no window meets the condition, return "Low"
    # if (toReturn != "High" or toReturn != "Mid"): toReturn = "Low"  # We only want to highest rating

    return toReturn