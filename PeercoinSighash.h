#ifndef HEXWALLET_PEERCOIN_SIGHASH_H
#define HEXWALLET_PEERCOIN_SIGHASH_H

#include "BitcoinTransaction.h"

namespace hexwallet {

// Peercoin consensus SIGHASH_ALL for P2PKH or witness-v0 P2WPKH.
// Versions 1/2 commit to nTime immediately after nVersion; version 3 omits
// nTime. The bounded input/output model and serializers are shared with the
// Bitcoin codec. No PSBT, fee-review or production signing capability is
// implied by this digest API. Other script forms/hash modes are unsupported.
TransactionError peercoin_sighash_all(const BitcoinSigningRequest &request,
                                      uint32_t transaction_time,
                                      size_t input_index, bool witness_v0,
                                      uint8_t out[kSha256Size]);
bool run_peercoin_sighash_self_tests();

}  // namespace hexwallet
#endif
