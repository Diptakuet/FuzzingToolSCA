#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <unistd.h>     // For getopt

#include "common.h"

const int X = 0x100000; // 1MB as a named constant
int LEN = 5000;  // Default value if not specified on the command line

int main(int argc, char *argv[]) {
    int opt;

    // Parse command-line options
    while ((opt = getopt(argc, argv, "L:")) != -1) {
        switch (opt) {
            case 'L':
                LEN = atoi(optarg);
                if (LEN <= 0) {
                    fprintf(stderr, "Invalid length: %s\n", optarg);
                    return 1;
                }
                break;
            default:
                fprintf(stderr, "Usage: %s -L <length>\n", argv[0]);
                return 1;
        }
    }

    clock_t local_temp_start = clock();

    uint8_t *b = (uint8_t*) malloc(6 * X * sizeof(uint8_t));
    if (!b) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    uint8_t *s = b;
    uint8_t *d = b + 2 * X;
    memset(s, 0xA, LEN);

    asm volatile (
        "movq $0, %%rcx\n\t"
        "loop_start_2:\n\t"
        "movq (%%rsi, %%rcx, 4), %%rax\n\t"
        "movq %%rax, (%%rdi, %%rcx, 4)\n\t"
        "incq %%rcx\n\t"
        "cmpq %[count], %%rcx\n\t"
        "jl loop_start_2\n\t"
        :
        : [count] "r" ((uint64_t)LEN), "S" (s), "D" (d)
        : "%rax", "%rcx", "memory"
    );

    for (int i = 0; i < LEN / 8; i += 8 * 8) {
        flush((void *)(s + i));
        flush((void *)(d + i));
    }

    free(b);
      
    clock_t local_temp_end = clock();
    double local_temp_start_minus_end_ms = (double)(local_temp_end - local_temp_start) / CLOCKS_PER_SEC * 1000.0;
    printf("Operation time: %f ms\n", local_temp_start_minus_end_ms);


    return 0;
}