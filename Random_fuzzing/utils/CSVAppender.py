###############################################################################################
#
#  CSVAppender.py: This class is used to add a column to a csv.  
#
#  Created by: Jonathan Tan (jona1115@iastate.edu)
#  Date      : 2/20/2024
#  
###########################################################################################
#  
#  MODIFICATION HISTORY:
# 
#  Ver          Who       Date	      Changes
#  -----        --------- ---------- ----------------------------------------------
#  1.00         Jonathan  2/20/2024  Created the file
# 
###############################################################################################


# Library imports
from loguru import logger
import pandas as pd
import numpy as np
import csv

# Project imports


# Start of code
class CSVAppender:
    # Constructor
    def __init__(self, givenInputFilePath, givenOutputFilePath, 
                 titleOfArrayOfValuesToAppend, arrayOfValuesToAppend=np.array([])):
        """
        This class will append a column (given np array) to the entire csv.
        """
        self.inputFilePath = givenInputFilePath
        self.outputFilePath = givenOutputFilePath
        self.titleOfArrayOfValuesToAppend = titleOfArrayOfValuesToAppend
        self.arrayOfValuesToAppend = arrayOfValuesToAppend

        self.append()
        
    ######################## Methods ########################
    def append(self):
        """
        This method will append a column to the entire csv.

        This method/function is partially written by, or written with the aid of, ChatGPT.
        """
        df = pd.read_csv(self.inputFilePath)

        # The corrected approach:
        # Instead of setting the title in the first row, we name the new column with this title
        # and start appending values from the array to the entire column.

        # Calculate the length of the DataFrame and the length of the array
        df_length = len(df)
        array_length = len(self.arrayOfValuesToAppend)
        
        # Create a new column with NaN values
        df[self.titleOfArrayOfValuesToAppend] = np.nan

        # Fill the new column with values from the array as much as it matches the DataFrame's length
        # If the array is longer, it's trimmed; if shorter or equal, it's used entirely.
        df[self.titleOfArrayOfValuesToAppend] = self.arrayOfValuesToAppend[:df_length]

        # Save the modified DataFrame to a new CSV file
        df.to_csv(self.outputFilePath, index=False)
