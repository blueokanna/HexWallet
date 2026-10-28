#ifndef HEXWALLET_CHIA_TRANSACTION_H
#define HEXWALLET_CHIA_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>

#include "ChainTransaction.h"

namespace hexwallet
{
  // Chia (XCH) standard-coin spends.
  //
  // The device never trusts a host-built solution: it accepts the coin, the
  // puzzle reveal and a list of CREATE_COIN conditions, verifies
  // sha256tree(reveal) == coin.puzzle_hash, displays every recipient and amount,
  // builds the delegated-puzzle solution itself and signs the AGG_SIG_ME message
  // with the synthetic key derived from the wallet key.
  //
  // Synthetic key: offset = sha256(pk48 || hidden_puzzle_hash) mod r,
  // synthetic_sk = (sk + offset) mod r (chia-blockchain
  // p2_delegated_puzzle_or_hidden_puzzle.calculate_synthetic_offset).
  //
  // AGG_SIG_ME signs msg || coin_name || genesis_challenge unhashed
  // (chia/consensus/condition_tools.py make_aggsig_final_message). msg is the
  // condition's data field, which the standard puzzle fills with
  // sha256tree(delegated_puzzle). The device builds that delegated puzzle
  // itself as `(q . conditions)` from the recipients and amounts it displays,
  // so the signed message is bound to the screen and the host cannot inject a
  // different condition list.
  //
  // Payload "XCH1":
  //   0  "XCH1"
  //   4  u8  network (0 = mainnet)
  //   5  u8  genesis_challenge[32]
  //   37 u8  hidden_puzzle_hash[32]
  //   69 u8 parent_coin_id[32]
  //   101 u8 puzzle_hash[32]
  //   133 u64 amount_be[8]           (mojo, 1 XCH = 1e12 mojo)
  //   141 u16 reveal_len_le          (1..1024)
  //       u8  puzzle_reveal[reveal_len]
  //       u8  condition_count        (1..16)
  //       condition_count x { u8 opcode (must be 51 = CREATE_COIN),
  //                           u8 puzzle_hash[32], u64 amount_be[8] }
  constexpr size_t kChiaMaxReveal = 1024;
  constexpr size_t kChiaMaxConditions = 16;
  constexpr size_t kChiaSignatureSize = 96;
  constexpr uint64_t kChiaMojoPerXch = 1000000000000ull;

  // Size of the encoded solution for the given number of conditions, so the
  // caller can size its output buffer.
  size_t chia_solution_size(uint8_t condition_count);

  ChainError chia_review_payload(const uint8_t *payload, size_t size,
                                 const char *sender, ChainReview *review,
                                 uint8_t digest[32]);

  // Returns the 96-byte BLS signature over the AGG_SIG_ME message. The rest of
  // the spend bundle (coin, reveal, solution) is assembled by the host from the
  // exact bytes the device displayed.
  ChainError chia_sign_payload(const uint8_t *payload, size_t size,
                               const uint8_t private_key[32], uint8_t *out,
                               size_t *in_out_size);

  bool run_chia_self_tests();

} // namespace hexwallet

#endif
