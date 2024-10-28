###############################################################################################
#  
#  Created by: Jonathan Tan (jona1115@iastate.edu)
#  Date      : 1/29/2024
#  
###########################################################################################
#  
#  CSVAverager.py: This class is for averaging multiple csv file of the same format.
#
#  Revision 1 (x/x/xxxx):
#
#
#  WARNING: This class ASSUMES the csv are in the same format, ie they should have 
#           the same title, same number of elements in a row, etc.
#  
###############################################################################################

# Library imports
from loguru import logger
from csv import writer
import pandas as pd
import numpy as np

# Project imports


# Start of code
class CSVAverager:
    # Constructor
    def __init__(self, givenListOfFiles, givenOutFilePath):
        """
        This class in a list of all the csv filenames that need to be averaged. 
        """
        self.listOfFiles = givenListOfFiles
        self.lenOfList = len(self.listOfFiles)
        self.outFilePath = givenOutFilePath


        # Auto run methods
        self.averageAllFiles()


    ######################## Methods ########################
    def averageAllFiles(self):
        """
        This function average the values all csv files of the same format.

        This method/function is partially written by, or written with the aid of, ChatGPT.
        """
        # Initialize an empty DataFrame for aggregated data
        aggregated_data = pd.DataFrame()

        # Loop through each file path in the list
        for file_path in self.listOfFiles:
            # Read the CSV file, skipping the header
            df = pd.read_csv(file_path, header=None, skiprows=1)
            # If aggregated_data is empty, copy the structure from the first file
            if aggregated_data.empty:
                aggregated_data = pd.DataFrame(0, index=df.index, columns=df.columns)
            # Sum the data from each file
            aggregated_data += df

        # Calculate the average
        averaged_data = aggregated_data / len(self.listOfFiles)

        # Write the header and the averaged data to the output file
        with open(self.outFilePath, 'w', newline='') as f:
            # Read the header from the first file
            with open(self.listOfFiles[0], 'r') as first_file:
                header = first_file.readline().strip()

            # Write the header
            f.write(header + '\n')

            # Initialize a CSV writer and write the averaged DataFrame
            csv_writer = writer(f)
            for index, row in averaged_data.iterrows():
                csv_writer.writerow(row)


    # def averageAllFiles(self):
    #     # Initialize a list to store DataFrames
    #     dataframes = []

    #     # Read each CSV file and append to the list
    #     for file_path in self.listOfFiles:
    #         df = pd.read_csv(file_path, skiprows=1, header=None)  # Skip the first row and do not use the first row as header
    #         dataframes.append(df)

    #     # Assuming all dataframes have the same structure and number of rows
    #     # Concatenate all DataFrames along the horizontal axis (axis=1) and ensure proper alignment
    #     concatenated_df = pd.concat(dataframes, axis=1)

    #     # Calculate the average across the horizontal axis (for each row)
    #     # We reshape the DataFrame to have 3 columns again and compute the mean along axis=1 (columns)
    #     num_files = len(self.listOfFiles)
    #     average_values = concatenated_df.values.reshape(-1, num_files).mean(axis=1).reshape(-1, 3)

    #     # Create a new DataFrame with the averaged values
    #     average_df = pd.DataFrame(average_values, columns=['Time', 'LLC-load-misses', 'LLC-store-misses'])

    #     # Read the header from the first file
    #     with open(self.listOfFiles[0], 'r') as f:
    #         header = f.readline().strip()

    #     # Write the averaged data to a new CSV file, including the header
    #     with open(self.outFilePath, 'w') as f:
    #         f.write(header + '\n')  # Write the header
    #         average_df.to_csv(f, index=False, header=False)  # Write the data without the index and without the default header
