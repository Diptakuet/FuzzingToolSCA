#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <unistd.h>     // For getopt

#include "common.h"


int initial_value = 500;  // Default value if not specified on the command line

int main(int argc, char *argv[]) {
    int opt;

    // Parse command-line options
    while ((opt = getopt(argc, argv, "L:")) != -1) {
        switch (opt) {
            case 'L':
                initial_value = atoi(optarg);
                if (initial_value <= 0) {
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

            const int X = {initial_value};

            int k = 1;
            for (int i = 0; i < X; ++i) {{
                for (int j = 0; j < X; ++j) {{
                    k += i * j; // No memory access to reduce side effect in the cache/memory domain
                }}
            }}
                        

      
    clock_t local_temp_end = clock();
    double local_temp_start_minus_end_ms = (double)(local_temp_end - local_temp_start) / CLOCKS_PER_SEC * 1000.0;
    //printf("Operation time:\n");
    printf("%f ms\n", local_temp_start_minus_end_ms);


    return 0;
}