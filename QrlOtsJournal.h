#ifndef HEXWALLET_QRL_OTS_JOURNAL_H
#define HEXWALLET_QRL_OTS_JOURNAL_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// Durable one-time-signature index reservation for QRL XMSS accounts.
//
// An XMSS account is a tree of 2^height one-time keys. Signing twice with the
// same leaf publishes two different signatures over one WOTS+ key and the
// account is gone: no recovery, no key rotation, and the network cannot reject
// the second signature in time. Every wallet that supports XMSS solves it the
// same way - the index is written to durable storage and read back *before* the
// signature exists, and the device refuses to sign when that proof is missing.
//
// This module is that proof and nothing else. It cannot build an XMSS
// signature; it only guarantees that an index it hands out can never be handed
// out again, including across a power loss in the middle of the write.
//
// Storage model: two slots holding the *same* self-checking record, bound to one
// account tag. A reservation writes the next index to both slots, reads both
// back, re-derives the mark from storage and only then returns the index. The
// redundancy is what makes a single failed or corrupted slot harmless:
//
//   * both records committed      -> the mark moved, the index is spent.
//   * neither record committed    -> nothing was handed out, nothing consumed.
//   * only one committed (torn)   -> the caller is told the write failed and
//                                    receives no index; the mark moves forward
//                                    anyway, so the leaf in flight is skipped
//                                    rather than reused.
//   * both unreadable             -> the mark is unknown, and the only safe
//                                    answer is to refuse. Starting over at zero
//                                    would reuse leaves.
//
// The worst case is one skipped leaf, which costs one of the 1024 signatures and
// leaks nothing.
//
// Residual risk this module cannot close on its own, stated so the signer has
// to deal with it: a blank journal is indistinguishable from a wiped journal.
// The custody layer must therefore treat "account exists in the secure element
// but the journal is blank" as a recovery event and refuse to sign, because
// re-initialising would hand out already-spent leaves.

constexpr size_t kQrlOtsSlotCount = 2;
constexpr uint32_t kQrlOtsTreeHeight = 10;
constexpr uint32_t kQrlOtsLeaves = 1U << kQrlOtsTreeHeight;
// magic[4] | tag[16] | index u32 | sequence u32 | crc32 u32
constexpr size_t kQrlOtsTagSize = 16;
constexpr size_t kQrlOtsRecordSize = 32;
constexpr size_t kQrlOtsSlotSize = kQrlOtsRecordSize;

enum class QrlOtsError : uint8_t {
  Ok = 0,
  // No slot holds a valid record for this account, so the high-water mark
  // cannot be proven and no index may be handed out.
  Unknown,
  // Every leaf of the tree has been reserved.
  Exhausted,
  // The record could not be persisted, or did not read back byte for byte.
  StorageFailure,
  // The durable journal belongs to another account tag.
  WrongAccount,
  InvalidArgument,
};

// Raw record as stored. The layout is fixed and little-endian so later firmware
// can still read what this one wrote.
struct QrlOtsRecord {
  uint8_t magic[4];
  uint8_t tag[kQrlOtsTagSize];
  uint32_t index;
  uint32_t sequence;
  uint32_t checksum;
};

// Port the platform implements. `read` returns false for blank or corrupt
// slots; it must not "repair" anything. `write` must be durable before it
// returns true - a cache that reports success early defeats the whole scheme,
// because the signature would exist while its index does not.
class QrlOtsStorage {
public:
  virtual ~QrlOtsStorage() = default;
  virtual bool read_slot(uint8_t slot, QrlOtsRecord *out) = 0;
  virtual bool write_slot(uint8_t slot, const QrlOtsRecord &record) = 0;
};

// Highest durable "next unused" index for `tag`. Ok means `out_index` is the
// leaf the next signature must use; Unknown means no slot proves anything.
QrlOtsError qrl_ots_high_water(QrlOtsStorage &storage,
                               const uint8_t tag[kQrlOtsTagSize],
                               uint32_t *out_index);

// Reserves one leaf and durably advances the mark past it. The index is only
// returned after the new record has been read back and the high-water mark has
// been re-derived from storage; on any failure nothing is handed out.
QrlOtsError qrl_ots_reserve(QrlOtsStorage &storage,
                            const uint8_t tag[kQrlOtsTagSize],
                            uint32_t *out_index);

// Binds a blank journal to `tag` at index zero. Refuses when any slot already
// holds a valid record, whatever tag it carries, so this can never reset a live
// account's counter.
QrlOtsError qrl_ots_initialise(QrlOtsStorage &storage,
                               const uint8_t tag[kQrlOtsTagSize]);

const char *qrl_ots_error_text(QrlOtsError error);

// Host-safe: sequence, exhaustion, read-back failure, lost-write recovery,
// cross-account refusal and the refuse-when-unknown rule.
bool run_qrl_ots_self_tests();

} // namespace hexwallet

#endif