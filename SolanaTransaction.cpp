#include "SolanaTransaction.h"
#include <string.h>
#include <stdio.h>
#include "CryptoExtended.h"
#include "CryptoPrimitives.h"
#include "SolanaDerivation.h"
#include "WalletConfig.h"

namespace hexwallet {
namespace {
constexpr size_t kMaxAccounts = 35; // additionally bounded by the 1232-byte wire limit
constexpr uint8_t kSystemProgram[32] = {};
// ComputeBudget111111111111111111111111111111
constexpr uint8_t kComputeBudget[32] = {
  3,6,70,111,229,33,23,50,255,236,173,186,114,195,155,231,
  188,140,229,187,197,247,18,107,44,67,155,58,64,0,0,0};
// TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA (classic SPL Token).
constexpr uint8_t kTokenProgram[32] = {
  6,221,246,225,215,101,161,147,217,203,225,70,206,235,121,172,
  28,180,133,237,95,91,55,145,58,140,245,133,126,255,0,169};
// TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb (Token-2022).
constexpr uint8_t kToken2022Program[32] = {
  6,221,246,225,238,117,143,222,24,66,93,188,228,108,205,218,
  182,26,252,77,131,185,13,39,254,189,249,40,216,161,139,252};
bool equal(const uint8_t *a, const uint8_t *b) {
  return crypto_constant_time_equal(a, b, 32);
}
uint64_t little(const uint8_t *p, size_t n) {
  uint64_t v = 0;
  for (size_t i = 0; i < n; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i);
  return v;
}
struct Reader {
  const uint8_t *data; size_t size; size_t offset;
  bool take(size_t count, const uint8_t **out) {
    if (count > size - offset) return false;
    *out = data + offset; offset += count; return true;
  }
  bool byte(uint8_t *out) {
    const uint8_t *p; if (!take(1, &p)) return false; *out = *p; return true;
  }
  bool compact(uint16_t *out) {
    uint32_t v = 0;
    for (unsigned i = 0; i < 3; ++i) {
      uint8_t b;
      if (!byte(&b) || (i == 2 && b > 3)) return false;
      v |= static_cast<uint32_t>(b & 127) << (7 * i);
      if (!(b & 128)) {
        if (i && (b & 127) == 0) return false;
        *out = static_cast<uint16_t>(v); return true;
      }
    }
    return false;
  }
};

SolanaError parse(const uint8_t *message, size_t size,
    const uint8_t payer[32], SolanaTransaction *out) {
  Reader reader = {message, size, 0};
  uint8_t required, readonly_signed, readonly_unsigned;
  if (!reader.byte(&required)) return SolanaError::Malformed;
  if (required & 128) {
    if (required != 128) return SolanaError::Unsupported;
    out->version0 = true;
    if (!reader.byte(&required)) return SolanaError::Malformed;
  }
  if (!reader.byte(&readonly_signed) || !reader.byte(&readonly_unsigned))
    return SolanaError::Malformed;
  if (required != 1 || readonly_signed != 0) return SolanaError::Unsupported;
  uint16_t account_count;
  if (!reader.compact(&account_count)) return SolanaError::Malformed;
  if (account_count < 3 || account_count > kMaxAccounts ||
      readonly_unsigned == 0 || readonly_unsigned >= account_count)
    return SolanaError::Unsupported;
  const uint8_t *accounts;
  if (!reader.take(static_cast<size_t>(account_count) * 32, &accounts))
    return SolanaError::Malformed;
  if (!equal(accounts, payer)) return SolanaError::WrongWallet;
  for (size_t i = 0; i < account_count; ++i)
    for (size_t j = 0; j < i; ++j)
      if (equal(accounts + 32*i, accounts + 32*j)) return SolanaError::Malformed;
  const size_t writable = account_count - readonly_unsigned;
  const uint8_t *blockhash;
  if (!reader.take(32, &blockhash) || equal(blockhash, kSystemProgram))
    return SolanaError::Malformed;
  uint16_t instruction_count;
  if (!reader.compact(&instruction_count)) return SolanaError::Malformed;
  if (instruction_count == 0 || instruction_count > kSolanaMaxTransfers + 2)
    return SolanaError::Unsupported;
  bool used[kMaxAccounts] = {}; used[0] = true;
  bool have_limit = false, have_price = false;
  uint32_t unit_limit = 0;
  uint64_t micro_price = 0;
  for (size_t i = 0; i < instruction_count; ++i) {
    uint8_t program;
    uint16_t index_count, data_size;
    const uint8_t *indices, *data;
    if (!reader.byte(&program) || !reader.compact(&index_count) ||
        !reader.take(index_count, &indices) || !reader.compact(&data_size) ||
        !reader.take(data_size, &data)) return SolanaError::Malformed;
    if (program >= account_count || program < writable) return SolanaError::Unsupported;
    for (size_t a = 0; a < index_count; ++a)
      if (indices[a] >= account_count) return SolanaError::Malformed;
    used[program] = true;
    if (equal(accounts + 32*program, kSystemProgram)) {
      if (data_size != 12 || little(data, 4) != 2 || index_count != 2 ||
          indices[0] != 0 || indices[1] == 0 || indices[1] >= writable)
        return SolanaError::Unsupported;
      if (out->transfer_count == kSolanaMaxTransfers) return SolanaError::Unsupported;
      const uint64_t amount = little(data + 4, 8);
      if (amount == 0 || UINT64_MAX - out->total_lamports < amount)
        return SolanaError::Malformed;
      SolanaTransfer &transfer = out->transfers[out->transfer_count++];
      memcpy(transfer.recipient, accounts + 32*indices[1], 32);
      memcpy(transfer.source, payer, 32);
      transfer.amount = amount; transfer.decimals = 9;
      transfer.kind = SolanaTransferKind::Native;
      out->total_lamports += amount;
      used[indices[1]] = true;
    } else if (equal(accounts + 32*program, kTokenProgram) ||
               equal(accounts + 32*program, kToken2022Program)) {
      const bool token2022 = equal(accounts + 32*program, kToken2022Program);
      // TransferChecked: [source, mint, destination, authority], u8(12), u64,
      // u8(decimals). Extra accounts would imply multisig or a transfer hook;
      // never blind-sign either.
      if (data_size != 10 || data[0] != 12 || index_count != 4 || indices[3] != 0 ||
          indices[0] == 0 || indices[2] == 0 || indices[0] == indices[2] ||
          indices[0] >= writable || indices[2] >= writable ||
          indices[1] < writable || indices[1] == program ||
          out->transfer_count == kSolanaMaxTransfers) return SolanaError::Unsupported;
      const uint64_t amount = little(data + 1, 8);
      if (amount == 0) return SolanaError::Malformed;
      const uint8_t *source = accounts + 32*indices[0];
      const uint8_t *mint = accounts + 32*indices[1];
      const uint8_t *destination = accounts + 32*indices[2];
      // A mint has one precision and an account has one mint. Reject contradictory
      // instructions even though the on-chain program would also reject them.
      for (size_t j = 0; j < out->transfer_count; ++j) {
        const SolanaTransfer &previous = out->transfers[j];
        if (previous.kind == SolanaTransferKind::Native) continue;
        const bool same_mint = equal(previous.mint, mint);
        if ((same_mint && previous.decimals != data[9]) || (!same_mint &&
            (equal(previous.source, source) || equal(previous.recipient, source) ||
             equal(previous.source, destination) || equal(previous.recipient, destination))))
          return SolanaError::Malformed;
      }
      SolanaTransfer &transfer = out->transfers[out->transfer_count++];
      memcpy(transfer.source, source, 32); memcpy(transfer.mint, mint, 32);
      memcpy(transfer.recipient, destination, 32);
      transfer.amount = amount; transfer.decimals = data[9];
      transfer.kind = token2022 ? SolanaTransferKind::SplToken2022
                                : SolanaTransferKind::SplToken;
      for (size_t j = 0; j < index_count; ++j) used[indices[j]] = true;
    } else if (equal(accounts + 32*program, kComputeBudget)) {
      if (out->transfer_count || index_count != 0 || data_size == 0)
        return SolanaError::Unsupported;
      if (data[0] == 2 && data_size == 5 && !have_limit) {
        unit_limit = static_cast<uint32_t>(little(data + 1, 4)); have_limit = true;
        if (unit_limit == 0 || unit_limit > 1400000) return SolanaError::FeePolicy;
      } else if (data[0] == 3 && data_size == 9 && !have_price) {
        micro_price = little(data + 1, 8); have_price = true;
      } else return SolanaError::Unsupported;
    } else return SolanaError::Unsupported;
  }
  if (out->transfer_count == 0 || have_limit != have_price) return SolanaError::Unsupported;
  for (size_t i = 0; i < account_count; ++i)
    if (!used[i]) return SolanaError::Unsupported;
  if (out->version0) {
    uint16_t lookups;
    if (!reader.compact(&lookups)) return SolanaError::Malformed;
    if (lookups != 0) return SolanaError::Unsupported;
  }
  if (reader.offset != size) return SolanaError::Malformed;
  if (have_price) {
    if (micro_price > UINT64_MAX / unit_limit) return SolanaError::FeePolicy;
    const uint64_t product = micro_price * unit_limit;
    out->priority_fee = product / 1000000 + (product % 1000000 != 0);
  }
  if (out->priority_fee > HEXWALLET_SOL_MAX_FEE_LAMPORTS ||
      kSolanaBaseFee > HEXWALLET_SOL_MAX_FEE_LAMPORTS - out->priority_fee)
    return SolanaError::FeePolicy;
  out->estimated_fee = kSolanaBaseFee + out->priority_fee;
  if (UINT64_MAX - out->total_lamports < out->estimated_fee) return SolanaError::Malformed;
  memcpy(out->payer, payer, 32); memcpy(out->blockhash, blockhash, 32);
  memcpy(out->message, message, size); out->message_size = static_cast<uint16_t>(size);
  return SolanaError::Ok;
}
}

bool solana_format_amount(const SolanaTransfer &transfer, char *out, size_t size) {
  if (out == nullptr || size == 0) return false;
  out[0] = '\0';
  if (transfer.kind != SolanaTransferKind::Native &&
      transfer.kind != SolanaTransferKind::SplToken &&
      transfer.kind != SolanaTransferKind::SplToken2022) return false;
  if (transfer.kind == SolanaTransferKind::Native && transfer.decimals != 9) return false;
  const char *unit = transfer.kind == SolanaTransferKind::Native ? "SOL" : "token";
  int written;
  if (transfer.decimals > 19) {
    written = snprintf(out, size, "%llu x 10^-%u token",
        static_cast<unsigned long long>(transfer.amount), unsigned(transfer.decimals));
  } else if (transfer.decimals == 0) {
    written = snprintf(out, size, "%llu %s",
        static_cast<unsigned long long>(transfer.amount), unit);
  } else {
    uint64_t divisor = 1;
    for (unsigned i = 0; i < transfer.decimals; ++i) divisor *= 10;
    written = snprintf(out, size, "%llu.%0*llu %s",
        static_cast<unsigned long long>(transfer.amount / divisor), int(transfer.decimals),
        static_cast<unsigned long long>(transfer.amount % divisor), unit);
  }
  if (written < 0 || static_cast<size_t>(written) >= size) { out[0] = '\0'; return false; }
  return true;
}

bool solana_derive_key(const uint8_t seed[kSeedSize], uint32_t index, uint8_t child[32]) {
  if (child == nullptr) return false;
  secure_zero(child, 32);
  uint32_t path[5];
  if (seed == nullptr || !solana_derivation_path(0, index, path)) return false;
  if (slip10_ed25519_derive(seed, kSeedSize, path, 5, child)) return true;
  secure_zero(child, 32); return false;
}

SolanaError solana_review_message(const uint8_t *message, size_t size,
    const uint8_t payer[32], SolanaTransaction *out) {
  if (out == nullptr) return SolanaError::InvalidArgument;
  secure_zero(out, sizeof(*out));
  if (message == nullptr || payer == nullptr || size == 0 || size > kSolanaMaxMessage)
    return SolanaError::InvalidArgument;
  const SolanaError error = parse(message, size, payer, out);
  if (error != SolanaError::Ok) secure_zero(out, sizeof(*out));
  return error;
}

SolanaError solana_sign_transaction(const SolanaTransaction &reviewed,
    const uint8_t seed[kSeedSize], uint8_t *out, size_t *in_out_size) {
  if (out == nullptr || in_out_size == nullptr) return SolanaError::InvalidArgument;
  const size_t capacity = *in_out_size;
  *in_out_size = 0;
  uint8_t child[32] = {}, payer[32] = {}, signature[64] = {};
  SolanaTransaction checked = {};
  SolanaError error = SolanaError::CryptoFailure;
  if (solana_derive_key(seed, reviewed.address_index, child) && ed25519_public_key(child, payer)) {
    error = solana_review_message(reviewed.message, reviewed.message_size, payer, &checked);
    if (error == SolanaError::Ok) {
      // Compare fields explicitly; padding bytes are not protocol state.
      if (checked.transfer_count != reviewed.transfer_count ||
          checked.total_lamports != reviewed.total_lamports ||
          checked.estimated_fee != reviewed.estimated_fee ||
          checked.priority_fee != reviewed.priority_fee ||
          checked.version0 != reviewed.version0 || !equal(checked.payer, reviewed.payer) ||
          !equal(checked.blockhash, reviewed.blockhash)) error = SolanaError::Malformed;
      for (size_t i = 0; i < checked.transfer_count && error == SolanaError::Ok; ++i)
        if (!equal(checked.transfers[i].recipient, reviewed.transfers[i].recipient) ||
            !equal(checked.transfers[i].source, reviewed.transfers[i].source) ||
            !equal(checked.transfers[i].mint, reviewed.transfers[i].mint) ||
            checked.transfers[i].amount != reviewed.transfers[i].amount ||
            checked.transfers[i].decimals != reviewed.transfers[i].decimals ||
            checked.transfers[i].kind != reviewed.transfers[i].kind)
          error = SolanaError::Malformed;
      if (error == SolanaError::Ok && capacity < checked.message_size + 65u)
        error = SolanaError::BufferTooSmall;
      if (error == SolanaError::Ok &&
          (!ed25519_sign(child, checked.message, checked.message_size, signature) ||
           !ed25519_verify(payer, checked.message, checked.message_size, signature)))
        error = SolanaError::CryptoFailure;
      if (error == SolanaError::Ok) {
        out[0] = 1; memcpy(out + 1, signature, 64);
        memcpy(out + 65, checked.message, checked.message_size);
        *in_out_size = checked.message_size + 65;
      }
    }
  }
  secure_zero(child, sizeof(child)); secure_zero(payer, sizeof(payer));
  secure_zero(signature, sizeof(signature)); secure_zero(&checked, sizeof(checked));
  return error;
}
}
