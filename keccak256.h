#ifndef __KECCAK256_H_
#define __KECCAK256_H_

#include <Arduino.h>
#include <stdint.h>

#define sha3_max_permutation_size 25
#define sha3_max_rate_in_qwords 24

typedef struct SHA3_CTX {
    uint64_t hash[sha3_max_permutation_size];
    uint64_t message[sha3_max_rate_in_qwords];
    uint16_t rest;

} SHA3_CTX;

void keccak_init(SHA3_CTX *ctx);
void keccak_update(SHA3_CTX *ctx, const unsigned char *msg, uint16_t size);
void keccak_final(SHA3_CTX *ctx, unsigned char* result);


#endif