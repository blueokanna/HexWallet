#pragma once
#include <stdint.h>

namespace hexwallet {
// WalletCli authenticates and serializes calls and owns the shared review gate.
// Cancel also destroys the sender's in-memory nonce.
struct BeamCliState { bool active; uint32_t expires_at; };
BeamCliState beam_cli_command(char *args, bool display_available);
void beam_cli_reset();
}
