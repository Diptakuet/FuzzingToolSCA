###############################################################################################
#  
#  Created by: Jonathan Tan (jona1115@iastate.edu)
#  Date      : 4/7/2024
#  
###########################################################################################
#  
#  settings_file_extractor.py: This file has the function to extract stuff from framework_settings.txt.
#                              This file is extremely hardcoded.
#  
#  Revision 1 (x/x/xxxx):
#  
###############################################################################################

def extract_value_from_settings_file(filename):
    # List to store the values
    values = []
    
    # Open the file for reading
    with open(filename, 'r') as file:
        # Iterate over each line in the file
        for line in file:
            # Check if the line contains a key-value pair and is not a comment
            if "=" in line and not line.strip().startswith("#"):
                # Extract the value part after the "=" and strip whitespace and quotes
                value = line.split("=", 1)[1].strip().strip('"')
                # Add the value to the list
                values.append(value)
                
    return values[0], values[1], values[2], values[3], values[4], values[5]