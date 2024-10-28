#include <stdint.h>

/**
 * Flush an address from the cache hierarchy
 * IN: (void *) address to be flushed
 */
void flush(void *);

/**
 * Read timestamp counter
 * RET: (uint64_t) CPU timestamp value
 */
uint64_t rdtsc();

/**
 * Access a memory address
 * IN: (void *) memory address
 */
void maccess(void *);

/**
 * Place a load fence instruction in the code
 */
void lfence();
