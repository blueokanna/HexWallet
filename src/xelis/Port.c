/* Constant-time zero test from libsodium sodium/utils.c, ISC license in ref10/LICENSE. */
#define SODIUM_STATIC 1
#include "ref10/utils.h"
int sodium_is_zero(const unsigned char *n, size_t size) {
    volatile unsigned char d = 0U;
    for (size_t i = 0; i < size; i++) d |= n[i];
    return 1 & ((d - 1) >> 8);
}
