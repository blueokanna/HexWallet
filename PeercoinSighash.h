#ifndef HEXWALLET_PEERCOIN_SIGHASH_H
#define HEXWALLET_PEERCOIN_SIGHASH_H

#include "BitcoinTransaction.h"

namespace hexwallet {
TransactionError peercoin_sighash_all(const BitcoinSigningRequest &request,
                                      uint32_t transaction_time,
                                      size_t input_index, bool witness_v0,
                                      uint8_t out[kSha256Size]);
bool run_peercoin_sighash_self_tests();

}  // namespace hexwallet
#endif
