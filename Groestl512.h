#ifndef HEXWALLET_GROESTL512_H
#define HEXWALLET_GROESTL512_H
#include <stddef.h>
#include <stdint.h>
namespace hexwallet {
// Grøstl-512 as submitted to the NIST SHA-3 competition (tweaked final round):
// 1024-bit state, 14 rounds, 64-byte digest taken as the last t bytes of
// Omega(x) = P(x) xor x. Every self-test value below comes from the official
// KAT_MCT/ShortMsgKAT_512.txt of the submission package, not from any
// third-party implementation.
constexpr size_t kGroestl512Digest = 64;
constexpr size_t kGroestl512Block = 128;
// Groestlcoin's base58 checksum is this hash applied twice, first four bytes.
bool groestl512(const uint8_t *data, size_t size, uint8_t out[kGroestl512Digest]);
bool run_groestl512_self_tests();
}  // namespace hexwallet
#endif
