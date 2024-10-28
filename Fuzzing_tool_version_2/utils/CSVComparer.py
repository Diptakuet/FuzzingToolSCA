###############################################################################################
#  
#  Created by: Jonathan Tan (jona1115@iastate.edu)
#  
###########################################################################################
#  
#  CSVComparer.py:
#  For testing all modules in CFileFuzzer.py.
#  
#  MODIFICATION HISTORY:
# 
#  Ver   Who       Date	      Changes
#  ----- --------- ---------- ----------------------------------------------
#  1.00	 Jonathan  5/13/2024  Created file.
#  
###############################################################################################

import pandas as pd
import numpy as np
import json

def compare_csv_files(file_a, file_b, range_a, range_b):
    """
    This function take in two CSVs, and two tuples. The tuple is in the format 
    (start_row, end_row). This function does no error checking so...~\^^/~

    It will average values in the range and compare them. Note, the range is the
    row number you see in excel, so if you want to average excel row 2 - 53, you 
    will pass in (2, 53). If you want to start from a row x and go to the last row,
    you can pass in (x, inf) for example (2, 1000000), this will automatically stop
    at the last row.

    @return the percentage difference of the mean in the range of file b and the
    mean in the range of file a, i.e. ((mean_b - mean_a) / mean_a) * 100 = %

    This method/function is partially written by, or written with the aid of, ChatGPT.
    """
    # Convert 1-based indexing to 0-based indexing for the row ranges
    start_a, end_a = range_a[0] - 1, range_a[1]
    start_b, end_b = range_b[0] - 1, range_b[1]
    
    # Read the CSV files into DataFrames
    df_a = pd.read_csv(file_a)
    df_b = pd.read_csv(file_b)
    
    # Replace NaNs with 0 for simplicity
    df_a.fillna(0, inplace=True)
    df_b.fillna(0, inplace=True)
    
    # Extract the specified ranges and calculate the mean for each column
    mean_a = df_a.iloc[start_a:end_a].mean()
    mean_b = df_b.iloc[start_b:end_b].mean()
    
    # Calculate the percentage difference for each column
    percent_difference = ((mean_b - mean_a) / mean_a) * 100
    
    # Convert the result to a dictionary
    percent_difference_dict = percent_difference.to_dict()
    
    return percent_difference_dict

def filter_abs_percent_greater_than_threshold(percent_diff_dict, threshold):
    # Filter the dictionary to include only items with values greater than 50%
    filtered_dict = {key: value for key, value in percent_diff_dict.items() if abs(value) > threshold}
    return filtered_dict

def filter_percent_greater_than_threshold(percent_diff_dict, threshold):
    # Filter the dictionary to include only items with values greater than 50%
    filtered_dict = {key: value for key, value in percent_diff_dict.items() if value > threshold}
    return filtered_dict

def pretty_print_dict(d):
    print(json.dumps(d, indent=4, sort_keys=True))

if __name__ == "__main__":
    # Test perf compability
    # folder_path = "/home/jonathan/berk_research/fuzzing_tool_for_SCA/python/collecteddata/"
    # file_a = folder_path + "moduletest_avged_2024_0515_1631_03_perf_out.csv"
    # file_b = folder_path + "moduletest_avged_2024_0515_1633_19_perf_out.csv"
    file_a = '/home/jonathan/berk_research/fuzzing_tool_for_SCA/python/collecteddata/moduletest_avged_2024_0515_1658_38_perf_out.csv'
    file_b = '/home/jonathan/berk_research/fuzzing_tool_for_SCA/python/collecteddata/moduletest_avged_2024_0515_1700_54_perf_out.csv'
    range_a = (2, 10000)
    range_b = (31, 10000)

    percent_diff_perf = compare_csv_files(file_a, file_b, range_a, range_b)
    pretty_print_dict(percent_diff_perf)

    percent_diff_greater_50 = filter_percent_greater_than_threshold(percent_diff_perf, 50)
    pretty_print_dict(percent_diff_greater_50)

    pass

    # Test PAPI compability
    # folder_path = "/home/jonathan/berk_research/fuzzing_tool_for_SCA/python/collecteddata/"
    # file_a = folder_path + "moduletest_avged_2024_0515_1631_55_PAPI_out.csv"
    # file_b = folder_path + "moduletest_avged_2024_0515_1634_32_PAPI_out.csv"
    range_a = (7, 99999)
    range_b = (7, 99999)

    percent_diff_papi = compare_csv_files(file_a, file_b, range_a, range_b)
    pretty_print_dict(percent_diff_papi)

    percent_diff_greater_50 = filter_percent_greater_than_threshold(percent_diff_papi, 50)
    pretty_print_dict(percent_diff_greater_50)

    # Create pretty excel
    # create_excel_from_dicts([percent_diff_perf, percent_diff_papi], './collecteddata/perf_vs_papi_test.xlsx')

    pass