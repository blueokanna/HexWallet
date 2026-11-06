#ifndef HEXWALLET_ADMISSION_H
#define HEXWALLET_ADMISSION_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// Identities this firmware must never present as a wallet.
//
// The catalog answers "what can this device do". This table answers the
// opposite question, and it exists because the failure mode that matters is a
// row appearing ahead of the implementation: once a chain is listed, every
// downstream claim - the phone catalog, the mining table, a screenshot - becomes
// a promise the firmware cannot keep.
//
// Each entry names the blocker that has to be cleared, not a preference. Two
// kinds appear here:
//
//   * protocol blockers - the chain cannot be signed the way this device signs
//     (Mimblewimble interactivity, shielded notes, FourQ identity, sharded
//     UTXO), or the primitives it needs are not in this tree;
//   * policy blockers - no SLIP-0044 coin type. Reusing another chain's type
//     would derive the same key material for two domains, so the chain stays
//     out until an upstream assignment exists.
//
// A chain leaves this table only together with its adapter, its vectors and a
// capability row - never by editing the catalog alone.
struct RefusedChain {
  const char *id;      // lowercase catalog-style id, never a ticker
  const char *name;
  uint32_t slip44;     // 0 when the chain has no registered coin type
  const char *blocker; // why it cannot ship today; empty is a self-test failure
  const char *requirement; // the artifact that would clear the blocker
};

size_t refused_chain_count();
const RefusedChain &refused_chain_at(size_t index);

// True when `id` is on the refusal list with a non-empty reason.
bool chain_is_refused(const char *id);

// Null when `id` is not refused. Callers use this to answer "why is this coin
// missing" from data instead of prose.
const RefusedChain *find_refused_chain(const char *id);

// One diagnostic line, already formatted: `id=<id> name="..." slip44=<n|none>
// blocker="..." requires="..."`. Returns false when the id is not refused or
// the buffer cannot hold the whole line, so a truncated answer is impossible.
// Lives here rather than in the CLI so the text is covered by the host tests.
bool refused_chain_describe(const char *id, char *out, size_t out_size);

// Absence invariant: no refused identity resolves to a network profile or a
// catalog entry, ids are unique and lowercase, and every reason is non-empty.
bool run_admission_self_tests();

}  // namespace hexwallet

#endif
