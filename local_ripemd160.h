#ifndef HEXWALLET_LOCAL_RIPEMD160_H
#define HEXWALLET_LOCAL_RIPEMD160_H

#include <stddef.h>
#include <stdint.h>

constexpr size_t kLocalRipemd160DigestSize = 20;

void local_ripemd160(const uint8_t *data, size_t data_size,
                     uint8_t digest[kLocalRipemd160DigestSize]);

#endif
