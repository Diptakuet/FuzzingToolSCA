#include <stdint.h>
#include <string.h>
#include <x86intrin.h>

/**
 * Flush an address from the cache hierarchy
 * IN: (void *) address to be flushed
 */
extern inline __attribute__((always_inline))
void flush(void *addr) {
    __builtin_ia32_clflush(addr);
    for (volatile int z = 0; z < 100; ++z);
}

/**
 * Read timestamp counter
 * RET: (uint64_t) CPU timestamp value
 */
extern inline __attribute__((always_inline))
uint64_t rdtsc()
{
    _mm_lfence();
    return __rdtsc();
}

/**
 * Access a memory address
 * IN: (void *) memory address
 */
extern inline __attribute__((always_inline))
void maccess(void *addr) {
    __asm__ __volatile__ ("movq (%%rdi), %%rdi;" :: "D" (addr));
}

/**
 * Place a load fence instruction in the code
 */
extern inline __attribute__((always_inline))
void lfence() {
    _mm_lfence();
}
