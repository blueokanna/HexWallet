#ifndef LOCAL_RIPEMD160_H
#define LOCAL_RIPEMD160_H

#include <stdint.h>
#include <stddef.h>

void local_ripemd160(const uint8_t* data, uint32_t data_len, uint8_t* digest_bytes);

#endif
