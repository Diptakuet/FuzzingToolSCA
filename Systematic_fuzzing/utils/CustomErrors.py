###############################################################################################
#  
#  Created by: Jonathan Tan (jona1115@iastate.edu)
#  Date      : 4/1/2024 (So it could be as a joke 🫢)
#  
###########################################################################################
#  
#  A file to store all custom error I want to use.
#  
#  Revision 1 (x/x/xxxx):
#  
###############################################################################################


class MakeError(Exception):
    """
    Compilation (make) error.
    """
    pass

class LenLTEZeroError(Exception):
    """
    LEN <= (Less than or equal to, LTE) 0.
    """
    pass

class DataCollectShPidAttachToZeroError(Exception):
    """
    data_collect.sh failed to attach to a PID.
    """
    pass