###############################################################################################
#  
#  Created by: Jonathan Tan (jona1115@iastate.edu)
#  Date      : 3/31/2024
#  
###########################################################################################
#  
#  CFileFuzzer.py: This class is used to connect to add instructions to a c file. For now,
#                  at least, all types of fuzz code will live in here. Once it gets crazy (
#                  a lot more fuzz types), we might wanna move it to individual files.
#  
#  MODIFICATION HISTORY:
# 
#  Ver   Who       Date	      Changes
#  ----- --------- ---------- ----------------------------------------------
#  1.00	 Jonathan  3/31/2024  Created file.
#  1.01  Jonathan  5/9/2024   Added more modules
#  2.00  Debopriya            Modified the modules to incorporate different settings
#
###############################################################################################

# Library imports
import threading
import time
from loguru import logger
import paramiko
from scp import SCPClient

# Project imports
from utils.SshConnector import SshConnector
from utils.CustomErrors import MakeError
from utils.CustomErrors import LenLTEZeroError


# Start of code
class CFileFuzzer:
    # Constructor
    def __init__(self, sshConnector, fileToFuzzPath, remoteTestingPath):
        self.sshConnector = sshConnector
        self.fileToFuzzPath = fileToFuzzPath
        self.remoteTestingPath = remoteTestingPath
        
        self.previousTriedLEN = 50000
        self.currentTryLEN = 50000

    def insertProfilingStuff(self):
        """
        This method will add necessary profiling code.
        This method will scp the code to the server to be compiled.
        """
        self.insertFuzzCodeFromString(self.fileToFuzzPath,
                                      "// >>>>> FUZZING PROFILLING variables init START",
                                      "// >>>>> FUZZING PROFILLING variables init END",
                                      """\
                                      #include <stdlib.h>     // malloc
                                      #include <stdio.h>      // for printf
                                      #include <stddef.h>     // for uint8_t, size_t etc
                                      #include <stdint.h>
                                      #include <time.h>       // For clock()
                                      #include <string.h>     // For memset
                                      #define ANSI_COLOR_RED     "\\x1b[31m"
                                      #define ANSI_COLOR_GREEN   "\\x1b[32m"
                                      #define ANSI_COLOR_YELLOW  "\\x1b[33m"
                                      #define ANSI_COLOR_BLUE    "\\x1b[34m"
                                      #define ANSI_COLOR_RESET   "\\x1b[0m"
                                      #define LOGI(s, ...) printf("[" ANSI_COLOR_BLUE "INFO" ANSI_COLOR_RESET " ] " s "\\n", ##__VA_ARGS__)
                                      #define LOGW(s, ...) printf("[" ANSI_COLOR_YELLOW "WARNG" ANSI_COLOR_RESET "] " s "\\n", ##__VA_ARGS__)
                                      #define LOGE(s, ...) printf("[" ANSI_COLOR_RED "ERROR" ANSI_COLOR_RESET "] " s "\\n", ##__VA_ARGS__)
                                      #define LOGD(s, ...) printf("[" ANSI_COLOR_GREEN "DEBUG" ANSI_COLOR_RESET "] " s "\\n", ##__VA_ARGS__)
                                      #define LOGI_NNL(s, ...) printf("[" ANSI_COLOR_BLUE "INFO" ANSI_COLOR_RESET " ] " s, ##__VA_ARGS__)		// No New Line
                                      #define LOGW_NNL(s, ...) printf("[" ANSI_COLOR_YELLOW "WARNG" ANSI_COLOR_RESET "] " s, ##__VA_ARGS__)	// No New Line
                                      #define LOGE_NNL(s, ...) printf("[" ANSI_COLOR_RED "ERROR" ANSI_COLOR_RESET "] " s, ##__VA_ARGS__)		// No New Line
                                      #define LOGD_NNL(s, ...) printf("[" ANSI_COLOR_GREEN "DEBUG" ANSI_COLOR_RESET "] " s, ##__VA_ARGS__)	// No New Line
                                      
                                      double total_fuzzing_time_ms = 0;
                                      double total_attack_code_time_ms = 0;
                                      // clock_t local_temp_start = 0;  Always reinit to 0 before using
                                      // clock_t local_temp_end = 0;  Always reinit to 0 before using
                                      // double local_temp_start_minus_end_ms = 0; // Always reinit to 0 before using\
                                      """)
        self.insertFuzzCodeFromString(self.fileToFuzzPath,
                                      "// >>>>> FUZZING total attack code profiling 1 start",
                                      "// >>>>> FUZZING total attack code profiling 1 end",
                                      """\
                                      clock_t time_for_main_attack_code_start = clock();\
                                      """)
        self.insertFuzzCodeFromString(self.fileToFuzzPath,
                                      "// >>>>> FUZZING total attack code profiling 2 start",
                                      "// >>>>> FUZZING total attack code profiling 2 end",
                                      """\
                                      clock_t time_for_main_attack_code_end = clock();
                                      double time_for_main_attack_code_start_minus_end_ms = (double) (time_for_main_attack_code_end - time_for_main_attack_code_start) / CLOCKS_PER_SEC * 1000.0;
                                      total_attack_code_time_ms += time_for_main_attack_code_start_minus_end_ms;\
                                      """)
        self.insertFuzzCodeFromString(self.fileToFuzzPath,
                                      "// >>>>> FUZZING total attack code profiling print results start",
                                      "// >>>>> FUZZING total attack code profiling print results end",
                                      """\
                                      LOGI("============================== Profilling ==============================");
                                      LOGI("Total fuzzing time (ms)\\t\\t: %10.4f", total_fuzzing_time_ms);
                                      LOGI("Total attack code time (ms)\\t: %10.4f (Including fuzzing time)", total_attack_code_time_ms);
                                      LOGI("Total attack code time (ms)\\t: %10.4f (Excluding fuzzing time)", total_attack_code_time_ms - total_fuzzing_time_ms);
                                      LOGI("Overhead in time (ms)\\t\\t: %10.4f", total_attack_code_time_ms/(total_attack_code_time_ms - total_fuzzing_time_ms));
                                      LOGI("========================================================================");\
                                      """)
        self.scpAndCompileCode()



    def start_timer(self, extraPrints=False):
        """
        Important: Call start_timer() before calling the modules.

        The task is to start a timer at the beginning of the modules.
        """
        fuzz_string = f"""\
        clock_t local_temp_start = clock();\
        """
    
        # Add fuzz to file
        self.insertFuzzCodeFromString(self.fileToFuzzPath,
                                        "// >>>>> timer on start",
                                        "// >>>>> timer on end",
                                        fuzz_string)
        self.scpAndCompileCode()

    def stop_timer(self, extraPrints=False):
        """
        Important: Call stop_timer() after calling all the modules.

        The task is to stop a timer at the end of adding all the modules. 
        Then, measure the time difference.
        """
        fuzz_string = f"""\
        clock_t local_temp_end = clock();
        double local_temp_start_minus_end_ms = (double)(local_temp_end - local_temp_start) / CLOCKS_PER_SEC * 1000.0;
        total_fuzzing_time_ms += local_temp_start_minus_end_ms;\
        """
        # Add fuzz to file
        self.insertFuzzCodeFromString(self.fileToFuzzPath,
                                        "// >>>>> timer off start",
                                        "// >>>>> timer off end",
                                        fuzz_string)
        self.scpAndCompileCode()


##############################################################################
# Module 1 
# perf: cache_misses (all the cache)
# PAPI: PAPI_L3_TCM
# pcm : LLC Misses
##############################################################################


    def increaseCacheMisses(self, initial_value, extraPrints=False):
        """
        Important: Call this function for fuzzing the code to impact the Cache_HPCs

        This method's job is to increase perf's "cache-misses" counters. This is done by adding
        a function that copies data from an array to another array that is far (1MB) away in memory.
        We ran tests and found that doing so will increase the "cache-misses" counter. The amount 
        of increase can be controlled by how big those arrays are, aka the "initial_value" (length) of the array.
        So, this function's job is to play with the "initial_value" to increase cache-misses.
        
        This method will scp the code to the server to be compiled.
        """
        
        # Generate the fuzz string
        fuzz_string = f"""\

            uint8_t *b = (uint8_t*) malloc(6 * 0x100000 * sizeof(uint8_t)); // 0x100000 = 1MB
            uint8_t *s = b;
            uint8_t *d = b + 2 * 0x100000; // 0x100000 = 1MB
            memset(s, 0xA, {initial_value}/*this number is generated by python framework*/);

            // fuzz_simple_lw_sw(s, d, FUZZ_SIMPLE_LW_SW_LEN):
            asm volatile (
                "movq $0, %%rcx\\n\\t"           // Initialize counter rcx to 0

                "loop_start_2:\\n\\t"
                "movq (%%rsi, %%rcx, 4), %%rax\\n\\t" // Load integer from source array. (%%esi, %%rcx, 4) means take value from esi+4*rcx, 4 because each element is uint32_t ie 4B
                "movq %%rax, (%%rdi, %%rcx, 4)\\n\\t" // Store it into destination array. (dest[rcx])
                
                "incq %%rcx\\n\\t"                // Increment counter
                "cmpq %[count], %%rcx\\n\\t"      // Compare counter with count
                "jl loop_start_2\\n\\t"             // If counter is less, loop

                : // Output operands
                // : "=r" (esi_value) // Output operands
                : [count] "r" ((uint64_t) {initial_value}/*this number is generated by python framework*/), "S" (s), "D" (d) // Input: count, src (esi), dest (edi)
                : "%rax", "%rcx", "memory"  // Clobbered: rax, ecx, and memory to indicate memory is being modified
            );

            for (int i = 0; i < {initial_value}/*this number is generated by python framework*//8/*X86_CACHELINE_SIZE_NUM_OF_B*/; i += 8*8/*X86_CACHELINE_SIZE_NUM_OF_B*/) {{
                flush((void *)(s + i));
                flush((void *)(d + i));
            }}
            
            free(b);

        """

        # Add fuzz to file
        self.insertFuzzCodeFromString(self.fileToFuzzPath,
                                        "// >>>>> cache_misses fuzz start",
                                        "// >>>>> cache_misses fuzz end",
                                        fuzz_string)
        self.scpAndCompileCode()


##############################################################################
# Module 2 
# perf: br_inst_retired.all_branches
# PAPI: PAPI_BR_INS 
##############################################################################
    def increaseBranchInstRetiredAllBranches(self, initial_value, extraPrints=False):
        # Generate the fuzz string
        fuzz_string = f"""\
            int retired_branches = 0;
            __asm__ volatile (
                    "movl $0, %%eax\\n\\t"                // Initialize counter to 0
                    "movl ${initial_value}, %%ecx\\n"    // Set loop counter (e.g., 1000 times)
                    "1:\\n\\t"                            // Label for the loop start
                    "incl %%eax\\n\\t"                    // Increment the EAX register

                    // Introduce multiple branch instructions
                    "testl %%eax, %%eax\\n\\t"            // Test EAX (logical compare to itself)
                    "jz 2f\\n\\t"                         // Jump to label 2 if zero
                    "jmp 3f\\n\\t"                        // Jump to label 3 unconditionally
                    "2:\\n\\t"                            // Label 2 (not reached in this setup)
                    "movl %%eax, %%eax\\n\\t"
                    "jmp 4f\\n\\t"
                    "3:\\n\\t"                            // Label 3
                    "movl %%eax, %%eax\\n\\t"
                    "4:\\n\\t"                            // Label 4
                    
                    "decl %%ecx\\n\\t"                    // Decrement loop counter
                    "jne 1b\\n\\t"                        // Jump to start of loop if not zero
                    : "=a" (retired_branches)           // Output: final value of EAX (not used)
                    :                                   // No input
                    : "%ecx"                            // Clobbered register
        );
        """



        # Add fuzz to file
        self.insertFuzzCodeFromString(self.fileToFuzzPath,
                                        "// >>>>> br_inst_retired fuzz start",
                                        "// >>>>> br_inst_retired fuzz end",
                                        fuzz_string)
        self.scpAndCompileCode()

##############################################################################
# Module 3 
# perf: br_misp_retired.all_branches
# PAPI: PAPI_BR_MISP 
###############################################################################
# Author: Debopriya Roy Dipta
##############################################################################

    def impactBranchMissPredictRetired(self,initial_value,extraPrints=False):
       ##version 1
       # Generate the fuzz string
        fuzz_string = f"""\
            int mispredict = 0;

            // Assembly block to create frequent branch mispredictions
            __asm__ volatile (
                "movl $0, %%eax\\n\\t"             // Initialize counter to 0
                "movl ${initial_value}, %%ecx\\n"            // Loop 1000 times
                "1:\\n\\t"                         // Label for the loop start
                "cmpl $0, %%eax\\n\\t"             // Compare counter with 0
                "je 2f\\n\\t"                      // Jump if equal to label 2
                "jmp 3f\\n\\t"                     // Jump to label 3
                "2:\\n\\t"                         // Label 2
                "movl $1, %%eax\\n\\t"             // Set counter to 1 to alternate path
                "jmp 4f\\n\\t"                     // Jump to label 4
                "3:\\n\\t"                         // Label 3
                "movl $0, %%eax\\n\\t"             // Set counter to 0 to alternate path
                "4:\\n\\t"                         // Label 4
                "decl %%ecx\\n\\t"                 // Decrement loop counter
                "jne 1b\\n\\t"                     // Jump to start of loop if not zero
                : "=a" (mispredict)              // Output: final value of EAX (not used)
                :                                // No input
                : "%ecx"                         // Clobbered register
            );
                        
        """

        # Add fuzz to file
        self.insertFuzzCodeFromString(self.fileToFuzzPath,
                                        "// >>>>> br_misp_retired fuzz start",
                                        "// >>>>> br_misp_retired fuzz end",
                                        fuzz_string)
        self.scpAndCompileCode()
    

##############################################################################
# Module 4
# perf: Instruction Retired
# PAPI: PAPI_TOT_INS
##############################################################################
    def decreaseTotalInstrCompleted(self, initial_value, extraPrints=False):
        # Generate the fuzz string
        fuzz_string = f"""\
            usleep({initial_value});  // The idea is to fuzz the number of actual instructions
                                // executed per unit time, so sleeping will decrease that


            //asm volatile ("nop");
        """

        # Add fuzz to file
        self.insertFuzzCodeFromString(self.fileToFuzzPath,
                                        "// >>>>> total_inst_retired fuzz start",
                                        "// >>>>> total_inst_retired fuzz end",
                                        fuzz_string)
        self.scpAndCompileCode()





###############################################################################
# Author: Debopriya Roy Dipta
# Module 5: Flush-Reload (randomizing attack )
####################################################################################
    def randomizingAttackPerEncryption(self, randomized_attack_count, extraPrints=False):
        # Generate the fuzz string
        fuzz_string = f"""\
            if (i%100 < {randomized_attack_count}){{\
            """
        fuzz_string2 = f"""\
            // asm volatile ("nop");\
        """
        # Add fuzz to file
        self.insertFuzzCodeFromString(self.fileToFuzzPath,
                                        "// >>>>> randomize_attack fuzz start",
                                        "// >>>>> randomize_attack fuzz end",
                                        fuzz_string)
        
        # self.insertFuzzCodeFromString(self.fileToFuzzPath,
        #                                 "// >>>>> Nop instruction fuzz start",
        #                                 "// >>>>> Nop instruction fuzz end",
        #                                 fuzz_string2)

        self.insertFuzzCodeFromString(self.fileToFuzzPath,
                                      "// >>>>> randomizing num of attack fuzz start 2",
                                      "// >>>>> randomizing num of attack fuzz end 2",
                                      """\
                                      }\
                                      """)
        
        self.insertFuzzCodeFromString(self.fileToFuzzPath,
                            "// >>>>> randomizing num of attack fuzz Te1 start 1",
                            "// >>>>> randomizing num of attack fuzz Te1 end 1",
                            fuzz_string)
        
        self.insertFuzzCodeFromString(self.fileToFuzzPath,
                            "// >>>>> randomizing num of attack fuzz Te1 start 2",
                            "// >>>>> randomizing num of attack fuzz Te1 end 2",
                            """\
                            }\
                            """)
        
        self.insertFuzzCodeFromString(self.fileToFuzzPath,
                            "// >>>>> randomizing num of attack fuzz Te2 start 1",
                            "// >>>>> randomizing num of attack fuzz Te2 end 1",
                            fuzz_string)
        
        self.insertFuzzCodeFromString(self.fileToFuzzPath,
                            "// >>>>> randomizing num of attack fuzz Te2 start 2",
                            "// >>>>> randomizing num of attack fuzz Te2 end 2",
                            """\
                            }\
                            """)
        self.insertFuzzCodeFromString(self.fileToFuzzPath,
                            "// >>>>> randomizing num of attack fuzz Te3 start 1",
                            "// >>>>> randomizing num of attack fuzz Te3 end 1",
                            fuzz_string)
        self.insertFuzzCodeFromString(self.fileToFuzzPath,
                            "// >>>>> randomizing num of attack fuzz Te3 start 2",
                            "// >>>>> randomizing num of attack fuzz Te3 end 2",
                            """\
                            }\
                            """)

        self.scpAndCompileCode()   



    ######################## Helper Methods ########################
    def inserFuzzCodeFromAnotherFile(self, source_file_path, start_marker, end_marker, fuzz_code_file_path):
        """
        This method will add stuff from fuzz_code_file_path in between start_marker and 
        end_marker in a file given by source_file_path.
        
        This method/function is partially written by, or written with the aid of, ChatGPT.
        """
        # Read fuzz code from the fuzz code file
        with open(fuzz_code_file_path, 'r') as fuzz_file:
            fuzz_code = fuzz_file.read()

        # Read the source C file
        with open(source_file_path, 'r') as file:
            lines = file.readlines()
        
        # Identify the start and end lines
        start_index = end_index = None
        for i, line in enumerate(lines):
            if start_marker in line:
                start_index = i
            elif end_marker in line:
                end_index = i
                break  # Stop searching once both markers are found
        
        if start_index is not None and end_index is not None:
            # Clear existing code between markers
            del lines[start_index+1:end_index]
            # Insert the fuzz code
            fuzz_lines = fuzz_code.split('\n')
            for i, line in enumerate(fuzz_lines):
                fuzz_lines[i] = line + '\n'  # Ensure each line ends with a newline
            lines[start_index+1:start_index+1] = fuzz_lines
        else:
            raise ValueError("Markers not found in the file.")
        
        # Write the modified code back to the file
        with open(source_file_path, 'w') as file:
            file.writelines(lines)

    def insertFuzzCodeFromString(self, source_file_path, start_marker, end_marker, fuzz_code):
        """
        This method will add String fuzz_code in between start_marker and end_marker in a file given
        by file_path.
        
        This method/function is partially written by, or written with the aid of, ChatGPT.
        """
        # Read the source C file
        with open(source_file_path, 'r') as file:
            lines = file.readlines()
        
        # Identify the start and end lines
        start_index = end_index = None
        for i, line in enumerate(lines):
            if start_marker in line:
                start_index = i
            elif end_marker in line:
                end_index = i
                break  # Stop searching once both markers are found
        
        if start_index is not None and end_index is not None:
            # Clear existing code between markers
            del lines[start_index+1:end_index]
            # Insert the fuzz code
            fuzz_lines = fuzz_code.split('\n')
            for i, line in enumerate(fuzz_lines):
                fuzz_lines[i] = line + '\n'  # Ensure each line ends with a newline
            lines[start_index+1:start_index+1] = fuzz_lines
        else:
            raise ValueError("Markers not found in the file.")
        
        # Write the modified code back to the file
        with open(source_file_path, 'w') as file:
            file.writelines(lines)

    @staticmethod
    def removeFuzzCodeBetweenMarkers(source_file_path, start_marker, end_marker):
        """
        This method will remove any content between start_marker and end_marker in a file given
        by source_file_path.
        
        This method/function is partially written by, or written with the aid of, ChatGPT.
        """
        # Read the source file
        with open(source_file_path, 'r') as file:
            lines = file.readlines()
        
        # Identify the start and end lines
        start_index = end_index = None
        for i, line in enumerate(lines):
            if start_marker in line:
                start_index = i
            elif end_marker in line:
                end_index = i
                break  # Stop searching once both markers are found
        
        if start_index is not None and end_index is not None:
            # Clear existing code between markers
            del lines[start_index+1:end_index]
        else:
            raise ValueError("Markers not found in the file.")
        
        # Write the modified code back to the file
        with open(source_file_path, 'w') as file:
            file.writelines(lines)

    def scpAndCompileCode(self, extraPrints=False):
        # SCP the file to the server
        self.sshConnector.scp_send(self.fileToFuzzPath, f"{self.remoteTestingPath}")

        # Compile the code remotely to make sure no compilation error
        flags_to_add = ""
        ret = self.sshConnector.execute_command(
                    f"(cd {self.remoteTestingPath} && make CFLAGS+=\"{flags_to_add}\")",
                    # f"(cd {self.remoteTestingPath} && make clean && make CFLAGS+=\"{flags_to_add}\")",
                    wantPrint=False) # Run make in the spectre dir, the "()" is for sub shell (https://superuser.com/questions/370575/how-to-run-make-file-from-any-directory)
        if (ret[0] < 0):
            logger.error(f"An error occured when compiling code. Error code: [{ret[0]}]\tError Message:\n{ret[1]}")
            raise MakeError("Error when compiling code in remote server!")
        else:
            return_message = f"\tRet Message:\n{ret[1]}"
            empty_string = ""
            logger.info(f"Code compiled without error, Ret: [{ret[0]}]\t{return_message if extraPrints else empty_string}")

    ######################## Getters&Setters ########################
    