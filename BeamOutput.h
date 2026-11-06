#pragma once

#include <stdint.h>

namespace hexwallet {
// Native BEAM, post-fork-6 confidential output, zero incubation, no asset proof.
// Full node wire encoding: flags 4/5, commitment x, packed range proof.
struct BeamOutput {
  uint8_t flags;
  uint8_t commitment_x[32];
  uint8_t proof[674];
};
static_assert(sizeof(BeamOutput) == 707);

enum class BeamCoinType : uint32_t { Regular = 0x6e6f726d, Change = 0x63686e67 };
struct BeamCoin {
  uint64_t index;
  BeamCoinType type;
  uint32_t subkey;
  uint64_t groth;
};

bool beam_create_output(const uint8_t bip39_seed[64], const BeamCoin &coin, BeamOutput &output);
bool beam_verify_output(const BeamOutput &output);
bool beam_recover_output(const uint8_t bip39_seed[64], const BeamOutput &output, BeamCoin &coin);
}
