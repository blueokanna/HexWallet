#pragma once

#include "../../BeamOutput.h"
#include "core/ecc_native.h"

namespace hexwallet::beam_keys {
void master_key(const uint8_t *seed, ECC::HKdf &master);
void switch_commitment(ECC::HKdf &master, const BeamCoin &coin, ECC::Scalar::Native &sk,
                       ECC::Point &commitment);
}
