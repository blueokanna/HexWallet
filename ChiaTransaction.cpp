#include "ChiaTransaction.h"

#include <mbedtls/bignum.h>
#include <stdio.h>
#include <string.h>

#include "BlsG2.h"
#include "ChainCommon.h"
#include "Clvm.h"
#include "CryptoExtended.h"
#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet
{
namespace
{

constexpr uint8_t kChiaNetworkMainnet = 0;
constexpr uint8_t kChiaCreateCoinOpcode = 51;
constexpr size_t kChiaPayloadFixedSize = 141;

struct ChiaCondition
{
  uint8_t puzzle_hash[32];
  uint64_t amount;
};

struct ChiaRequest
{
  uint8_t network;
  uint8_t genesis_challenge[32];
  uint8_t hidden_puzzle_hash[32];
  uint8_t parent_coin_id[32];
  uint8_t puzzle_hash[32];
  uint64_t amount;
  const uint8_t *reveal;
  uint16_t reveal_size;
  uint8_t condition_count;
  ChiaCondition conditions[kChiaMaxConditions];
};

struct Reader
{
  const uint8_t *data;
  size_t size;
  size_t offset;

  bool take(const uint8_t **out, size_t count)
  {
    if (count > size - offset) return false;
    *out = data + offset;
    offset += count;
    return true;
  }
  bool u8(uint8_t *out)
  {
    const uint8_t *p = nullptr;
    if (!take(&p, 1)) return false;
    *out = *p;
    return true;
  }
  bool u16_le(uint16_t *out)
  {
    const uint8_t *p = nullptr;
    if (!take(&p, 2)) return false;
    *out = static_cast<uint16_t>(p[0] | (p[1] << 8));
    return true;
  }
  bool u64_be(uint64_t *out)
  {
    const uint8_t *p = nullptr;
    if (!take(&p, 8)) return false;
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) value = (value << 8) | p[i];
    *out = value;
    return true;
  }
};

ChainError parse_payload(const uint8_t *payload, size_t size,
                         ChiaRequest *request)
{
  if (payload == nullptr || request == nullptr) return ChainError::InvalidArgument;
  if (size < kChiaPayloadFixedSize || memcmp(payload, "XCH1", 4) != 0) {
    return ChainError::Malformed;
  }
  memset(request, 0, sizeof(*request));
  Reader reader = {payload, size, 4};
  if (!reader.u8(&request->network)) return ChainError::Malformed;
  if (request->network != kChiaNetworkMainnet) return ChainError::WrongNetwork;
  const uint8_t *field = nullptr;
  if (!reader.take(&field, 32)) return ChainError::Malformed;
  memcpy(request->genesis_challenge, field, 32);
  if (!reader.take(&field, 32)) return ChainError::Malformed;
  memcpy(request->hidden_puzzle_hash, field, 32);
  if (!reader.take(&field, 32)) return ChainError::Malformed;
  memcpy(request->parent_coin_id, field, 32);
  if (!reader.take(&field, 32)) return ChainError::Malformed;
  memcpy(request->puzzle_hash, field, 32);
  if (!reader.u64_be(&request->amount)) return ChainError::Malformed;
  if (request->amount == 0) return ChainError::InvalidAmount;
  if (!reader.u16_le(&request->reveal_size)) return ChainError::Malformed;
  if (request->reveal_size == 0 || request->reveal_size > kChiaMaxReveal) {
    return ChainError::Malformed;
  }
  if (!reader.take(&request->reveal, request->reveal_size)) {
    return ChainError::Malformed;
  }
  if (!reader.u8(&request->condition_count)) return ChainError::Malformed;
  if (request->condition_count == 0 ||
      request->condition_count > kChiaMaxConditions) {
    return ChainError::Malformed;
  }
  for (uint8_t i = 0; i < request->condition_count; ++i)
  {
    uint8_t opcode = 0;
    if (!reader.u8(&opcode)) return ChainError::Malformed;
    // Only CREATE_COIN is admitted: anything else (fee, ASSERT_*, AGG_SIG_*)
    // would change what the user sees versus what is signed.
    if (opcode != kChiaCreateCoinOpcode) return ChainError::Unsupported;
    if (!reader.take(&field, 32)) return ChainError::Malformed;
    memcpy(request->conditions[i].puzzle_hash, field, 32);
    if (!reader.u64_be(&request->conditions[i].amount)) {
      return ChainError::Malformed;
    }
    if (request->conditions[i].amount == 0) return ChainError::InvalidAmount;
  }
  if (reader.offset != reader.size) return ChainError::Malformed;
  return ChainError::Ok;
}

// sha256tree(puzzle_reveal) must equal the coin's puzzle hash, otherwise the
// host is trying to make the device sign a coin it cannot describe.
bool reveal_matches(const ChiaRequest &request)
{
  static ClvmArena arena;
  clvm_arena_init(&arena);
  uint16_t root = 0;
  if (!clvm_parse(&arena, request.reveal, request.reveal_size, &root)) return false;
  uint8_t hash[32];
  if (!clvm_tree_hash(&arena, root, hash)) return false;
  return chain_constant_time_equal(hash, request.puzzle_hash, 32);
}

// offset = sha256(pk || hidden_puzzle_hash) mod r
bool synthetic_offset(const uint8_t public_key[48], const uint8_t hidden[32],
                      uint8_t out[32])
{
  uint8_t preimage[80];
  memcpy(preimage, public_key, 48);
  memcpy(preimage + 48, hidden, 32);
  uint8_t digest[32];
  if (!crypto_sha256(preimage, sizeof(preimage), digest)) return false;
  static const char kOrder[] =
      "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";
  mbedtls_mpi order, value;
  mbedtls_mpi_init(&order);
  mbedtls_mpi_init(&value);
  bool ok = mbedtls_mpi_read_string(&order, 16, kOrder) == 0 &&
            mbedtls_mpi_read_binary(&value, digest, 32) == 0 &&
            mbedtls_mpi_mod_mpi(&value, &value, &order) == 0 &&
            mbedtls_mpi_write_binary(&value, out, 32) == 0;
  mbedtls_mpi_free(&order);
  mbedtls_mpi_free(&value);
  secure_zero(digest, sizeof(digest));
  return ok;
}

// synthetic_sk = (sk + offset) mod r
bool synthetic_secret_key(const uint8_t secret_key[32], const uint8_t offset[32],
                          uint8_t out[32])
{
  static const char kOrder[] =
      "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";
  mbedtls_mpi order, secret, delta, sum;
  mbedtls_mpi_init(&order);
  mbedtls_mpi_init(&secret);
  mbedtls_mpi_init(&delta);
  mbedtls_mpi_init(&sum);
  bool ok = mbedtls_mpi_read_string(&order, 16, kOrder) == 0 &&
            mbedtls_mpi_read_binary(&secret, secret_key, 32) == 0 &&
            mbedtls_mpi_read_binary(&delta, offset, 32) == 0 &&
            mbedtls_mpi_add_mpi(&sum, &secret, &delta) == 0 &&
            mbedtls_mpi_mod_mpi(&sum, &sum, &order) == 0 &&
            mbedtls_mpi_write_binary(&sum, out, 32) == 0;
  mbedtls_mpi_free(&order);
  mbedtls_mpi_free(&secret);
  mbedtls_mpi_free(&delta);
  mbedtls_mpi_free(&sum);
  return ok;
}

// Minimal big-endian CLVM integer encoding (no leading zero bytes, empty for 0).
size_t clvm_int(uint64_t value, uint8_t out[8])
{
  if (value == 0) return 0;
  uint8_t buffer[8];
  size_t size = 0;
  while (value != 0)
  {
    buffer[size++] = static_cast<uint8_t>(value & 0xff);
    value >>= 8;
  }
  for (size_t i = 0; i < size; ++i) out[i] = buffer[size - 1 - i];
  return size;
}

bool write_atom(const uint8_t *data, size_t size, uint8_t *out, size_t capacity,
                size_t *offset)
{
  if (size == 0)
  {
    if (*offset + 1 > capacity) return false;
    out[(*offset)++] = 0x80;
    return true;
  }
  if (size == 1 && data[0] <= 0x7f)
  {
    if (*offset + 1 > capacity) return false;
    out[(*offset)++] = data[0];
    return true;
  }
  size_t prefix = 0;
  uint8_t header[3];
  if (size < 0x40)
  {
    header[0] = static_cast<uint8_t>(0x80 | size);
    prefix = 1;
  }
  else if (size < 0x2000)
  {
    header[0] = static_cast<uint8_t>(0xc0 | (size >> 8));
    header[1] = static_cast<uint8_t>(size & 0xff);
    prefix = 2;
  }
  else
  {
    return false;
  }
  if (*offset + prefix + size > capacity) return false;
  memcpy(out + *offset, header, prefix);
  *offset += prefix;
  memcpy(out + *offset, data, size);
  *offset += size;
  return true;
}

size_t clvm_int_atom_size(uint64_t value)
{
  uint8_t buffer[8];
  const size_t size = clvm_int(value, buffer);
  if (size == 0) return 1;             // nil
  if (size == 1) return 1;             // single byte shortcut
  if (size < 0x40) return 1 + size;    // 0x80|size
  return 2 + size;                     // 0xc0|hi, lo
}

} // namespace

size_t chia_solution_size(uint8_t condition_count)
{
  // (nil . (((1 . conditions)) . (0 . nil)))
  // Each condition is (51 . (puzzle_hash . (amount . nil))).
  size_t size = 1;  // nil head
  size += 1;        // cons
  size += 1;        // atom 1
  size += 1;        // cons
  for (uint8_t i = 0; i < condition_count; ++i)
  {
    size += 1;    // cons
    size += 1;    // atom 51
    size += 1;    // cons
    size += 33;   // 32-byte puzzle hash atom
    size += 1;    // cons
    size += clvm_int_atom_size(0);  // placeholder, widened below
    size += 1;    // nil terminator
  }
  size += 1;  // nil (conditions tail)
  size += 1;  // cons
  size += 1;  // atom 0
  size += 1;  // nil
  // Amounts are variable width; add the worst case for eight-byte integers.
  size += static_cast<size_t>(condition_count) * 9;
  return size;
}

namespace
{

// Builds [[], (1 . conditions), 0] with the CREATE_COIN conditions the device
// displayed.
bool build_solution(const ChiaRequest &request, uint8_t *out, size_t capacity,
                    size_t *out_size)
{
  // (nil . ((1 . conditions) . (0 . nil))), where each condition is
  // (51 . (puzzle_hash . (amount . nil))) wrapped in its own list cons.
  size_t offset = 0;
  struct Byte
  {
    uint8_t value;
  };
  const Byte head[] = {{0xff}, {0x80}, {0xff}, {0xff}, {0x01}};
  for (size_t i = 0; i < sizeof(head) / sizeof(head[0]); ++i)
  {
    if (offset + 1 > capacity) return false;
    out[offset++] = head[i].value;
  }
  for (uint8_t i = 0; i < request.condition_count; ++i)
  {
    const uint8_t open_condition[] = {0xff, 0xff, kChiaCreateCoinOpcode};
    for (size_t b = 0; b < sizeof(open_condition); ++b)
    {
      if (offset + 1 > capacity) return false;
      out[offset++] = open_condition[b];
    }
    if (offset + 1 > capacity) return false;
    out[offset++] = 0xff;
    if (!write_atom(request.conditions[i].puzzle_hash, 32, out, capacity, &offset)) {
      return false;
    }
    if (offset + 1 > capacity) return false;
    out[offset++] = 0xff;
    uint8_t amount[8];
    const size_t amount_size = clvm_int(request.conditions[i].amount, amount);
    if (!write_atom(amount, amount_size, out, capacity, &offset)) return false;
    if (offset + 1 > capacity) return false;
    out[offset++] = 0x80;  // condition nil
  }
  const uint8_t tail[] = {0x80, 0xff, 0x00, 0x80};  // list nil, (0 . nil)
  for (size_t i = 0; i < sizeof(tail); ++i)
  {
    if (offset + 1 > capacity) return false;
    out[offset++] = tail[i];
  }
  *out_size = offset;
  return true;
}
// coin name = sha256(parent_coin_id || puzzle_hash || clvm_int(amount))
bool coin_name(const ChiaRequest &request, uint8_t out[32])
{
  uint8_t buffer[32 + 32 + 8];
  memcpy(buffer, request.parent_coin_id, 32);
  memcpy(buffer + 32, request.puzzle_hash, 32);
  const size_t amount_size = clvm_int(request.amount, buffer + 64);
  return crypto_sha256(buffer, 64 + amount_size, out);
}

// sha256tree of the delegated puzzle `(q . conditions)` that the device is
// about to spend: the standard puzzle signs sha256tree(delegated_puzzle) as the
// AGG_SIG_ME data field, so computing it here binds the signature to exactly
// the recipients and amounts the screen showed. A host-supplied value would
// let the signature cover a different condition list.
bool conditions_tree_hash(const ChiaRequest &request, uint8_t out[32])
{
  uint8_t nil_hash[32];
  if (!clvm_atom_hash(nullptr, 0, nil_hash)) { return false; }
  uint8_t list[32];
  memcpy(list, nil_hash, sizeof(list));
  for (size_t index = request.condition_count; index-- > 0;) {
    const ChiaCondition &condition = request.conditions[index];
    uint8_t amount_bytes[8];
    size_t amount_size = 0;
    uint64_t value = condition.amount;
    while (value != 0) {
      amount_bytes[amount_size++] = static_cast<uint8_t>(value & 0xff);
      value >>= 8;
    }
    for (size_t low = 0, high = amount_size; low + 1 < high; ++low, --high) {
      const uint8_t swap = amount_bytes[low];
      amount_bytes[low] = amount_bytes[high - 1];
      amount_bytes[high - 1] = swap;
    }
    const uint8_t opcode = kChiaCreateCoinOpcode;
    uint8_t opcode_hash[32];
    uint8_t puzzle_hash[32];
    uint8_t amount_hash[32];
    uint8_t tail[32];
    uint8_t condition_hash[32];
    if (!clvm_atom_hash(&opcode, 1, opcode_hash) ||
        !clvm_atom_hash(condition.puzzle_hash, 32, puzzle_hash) ||
        !clvm_atom_hash(amount_bytes, amount_size, amount_hash) ||
        // (amount . nil)
        !clvm_pair_hash(amount_hash, nil_hash, tail) ||
        // (puzzle_hash amount . nil)
        !clvm_pair_hash(puzzle_hash, tail, tail) ||
        // (51 puzzle_hash amount . nil)
        !clvm_pair_hash(opcode_hash, tail, condition_hash) ||
        !clvm_pair_hash(condition_hash, list, list)) {
      return false;
    }
  }
  const uint8_t quote = 0x01;
  uint8_t quote_hash[32];
  // (q . conditions)
  return clvm_atom_hash(&quote, 1, quote_hash) &&
         clvm_pair_hash(quote_hash, list, out);
}

// AGG_SIG_ME final message (chia/consensus/condition_tools.py
// make_aggsig_final_message): msg || addendum || additional_data, i.e.
// condition_data || coin_name || genesis_challenge, raw and unhashed.
bool agg_sig_message(const ChiaRequest &request, uint8_t out[96])
{
  uint8_t name[32];
  if (!coin_name(request, name)) { return false; }
  if (!conditions_tree_hash(request, out)) { return false; }
  memcpy(out + 32, name, 32);
  memcpy(out + 64, request.genesis_challenge, 32);
  return true;
}

bool synthetic_key(const uint8_t private_key[32], const ChiaRequest &request,
                   uint8_t out_synthetic_sk[32])
{
  uint8_t public_key[kBlsG1CompressedSize];
  if (!bls12_381_g1_public_key(private_key, public_key)) return false;
  uint8_t offset[32];
  if (!synthetic_offset(public_key, request.hidden_puzzle_hash, offset)) {
    return false;
  }
  const bool ok = synthetic_secret_key(private_key, offset, out_synthetic_sk);
  secure_zero(offset, sizeof(offset));
  return ok;
}

} // namespace

ChainError chia_review_payload(const uint8_t *payload, size_t size,
                               const char *sender, ChainReview *review,
                               uint8_t digest[32])
{
  if (payload == nullptr || sender == nullptr || review == nullptr ||
      digest == nullptr) {
    return ChainError::InvalidArgument;
  }
  ChiaRequest request;
  ChainError error = parse_payload(payload, size, &request);
  if (error != ChainError::Ok) return error;
  if (!reveal_matches(request)) return ChainError::WrongNetwork;
  uint8_t agg_message[96];
  if (!agg_sig_message(request, agg_message) ||
      !crypto_sha256(agg_message, sizeof(agg_message), digest)) {
    return ChainError::CryptoFailure;
  }
  secure_zero(agg_message, sizeof(agg_message));

  memset(review, 0, sizeof(*review));
  strncpy(review->symbol, "XCH", sizeof(review->symbol) - 1);
  strncpy(review->sender, sender, sizeof(review->sender) - 1);
  // The first CREATE_COIN is the payment; the rest is change or split outputs.
  if (!bech32_encode("xch", request.conditions[0].puzzle_hash, 32,
                     review->recipient, sizeof(review->recipient), true)) {
    return ChainError::Malformed;
  }
  if (!chain_format_units(request.conditions[0].amount, 12, "XCH",
                          review->amount, sizeof(review->amount))) {
    return ChainError::BufferTooSmall;
  }
  uint64_t total = 0;
  for (uint8_t i = 0; i < request.condition_count; ++i) {
    total += request.conditions[i].amount;
  }
  if (total >= request.amount)
  {
    char fee[kChainMaxAmount];
    if (!chain_format_units(total - request.amount, 12, "XCH", fee,
                            sizeof(fee))) {
      return ChainError::BufferTooSmall;
    }
    snprintf(review->fee, sizeof(review->fee), "%s", fee);
  }
  else
  {
    strncpy(review->fee, "OUTPUTS EXCEED COIN", sizeof(review->fee) - 1);
  }
  static const char kHashDigits[] = "0123456789abcdef";
  uint8_t bound[32];
  if (!conditions_tree_hash(request, bound)) return ChainError::CryptoFailure;
  char coin_hex[9];
  char puzzle_hex[9];
  for (size_t i = 0; i < 4; ++i)
  {
    coin_hex[i * 2] = kHashDigits[bound[i] >> 4];
    coin_hex[i * 2 + 1] = kHashDigits[bound[i] & 0x0f];
    puzzle_hex[i * 2] = kHashDigits[request.hidden_puzzle_hash[i] >> 4];
    puzzle_hex[i * 2 + 1] = kHashDigits[request.hidden_puzzle_hash[i] & 0x0f];
  }
  secure_zero(bound, sizeof(bound));
  coin_hex[8] = '\0';
  puzzle_hex[8] = '\0';
  // BOUND is sha256tree of the delegated puzzle the device itself built from
  // the conditions above; that hash is what AGG_SIG_ME signs, so the signature
  // cannot cover a recipient the screen never showed.
  snprintf(review->extra, sizeof(review->extra),
           "OUTPUTS %u\nREVEAL %u B\nBOUND %s\nHIDDEN %s",
           static_cast<unsigned>(request.condition_count),
           static_cast<unsigned>(request.reveal_size), coin_hex, puzzle_hex);
  return ChainError::Ok;
}

ChainError chia_sign_payload(const uint8_t *payload, size_t size,
                             const uint8_t private_key[32], uint8_t *out,
                             size_t *in_out_size)
{
  if (payload == nullptr || private_key == nullptr || out == nullptr ||
      in_out_size == nullptr) {
    return ChainError::InvalidArgument;
  }
  const size_t capacity = *in_out_size;
  *in_out_size = 0;
  ChiaRequest request;
  ChainError error = parse_payload(payload, size, &request);
  if (error != ChainError::Ok) return error;
  if (!reveal_matches(request)) return ChainError::WrongNetwork;

  uint8_t message[96];
  if (!agg_sig_message(request, message)) return ChainError::CryptoFailure;
  uint8_t secret[32];
  if (!synthetic_key(private_key, request, secret)) {
    secure_zero(message, sizeof(message));
    return ChainError::CryptoFailure;
  }
  uint8_t solution[1024];
  size_t solution_size = 0;
  bool ok = build_solution(request, solution, sizeof(solution), &solution_size);

  // Output: signature(96) || coin_name(32) || solution_len_le(2) || solution.
  const size_t needed = kChiaSignatureSize + 32 + 2 + solution_size;
  if (ok && needed > capacity) ok = false;
  if (ok)
  {
    uint8_t coin[32];
    ok = coin_name(request, coin) &&
         bls12_381_g2_sign_augmented(secret, message, sizeof(message), out);
    if (ok)
    {
      memcpy(out + kChiaSignatureSize, coin, 32);
      out[kChiaSignatureSize + 32] =
          static_cast<uint8_t>(solution_size & 0xff);
      out[kChiaSignatureSize + 33] =
          static_cast<uint8_t>((solution_size >> 8) & 0xff);
      memcpy(out + kChiaSignatureSize + 34, solution, solution_size);
      *in_out_size = needed;
    }
    secure_zero(coin, sizeof(coin));
  }
  secure_zero(secret, sizeof(secret));
  secure_zero(message, sizeof(message));
  secure_zero(solution, sizeof(solution));
  return ok ? ChainError::Ok : ChainError::BufferTooSmall;
}

bool run_chia_self_tests()
{
  // Constants computed independently in Python from the documented formulas.
  // sk = 1 gives the BLS12-381 G1 generator as the public key.
  static const uint8_t kGenerator[48] = {
      0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c,
      0x4f, 0xa9, 0xac, 0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05,
      0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b, 0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f,
      0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb};
  static const uint8_t kExpectedOffset[32] = {
      0x30, 0x85, 0xf9, 0x3d, 0x78, 0x80, 0x94, 0xce, 0x24, 0xfb, 0x4d,
      0xb6, 0x43, 0x61, 0x93, 0xa5, 0x53, 0xc0, 0xee, 0x1e, 0x36, 0x81,
      0x83, 0xba, 0xb7, 0x28, 0xa6, 0x76, 0x1f, 0x63, 0xd5, 0xc2};
  static const uint8_t kExpectedCoin[32] = {
      0x31, 0xe5, 0x9c, 0x4f, 0xe2, 0x9f, 0x6f, 0x38, 0x37, 0x69, 0xbe,
      0xfb, 0x41, 0x83, 0x25, 0x41, 0x80, 0x88, 0x00, 0xd3, 0xfd, 0x4a,
      0xa3, 0x46, 0x1a, 0xf7, 0xc7, 0x3d, 0xbf, 0x8c, 0x5c, 0x93};
  static const uint8_t kExpectedSolution[] = {
      0xff, 0x80, 0xff, 0xff, 0x01, 0xff, 0xff, 0x33, 0xff, 0xa0, 0x44, 0x44,
      0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
      0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
      0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0xff, 0x85, 0xe8, 0xd4, 0xa5, 0x10,
      0x00, 0x80, 0x80, 0xff, 0x00, 0x80};

  uint8_t hidden[32];
  memset(hidden, 0x11, sizeof(hidden));
  uint8_t offset[32] = {};
  if (!synthetic_offset(kGenerator, hidden, offset)) { return false; }
  if (!chain_constant_time_equal(offset, kExpectedOffset, 32)) {
   
    return false;
  }

  ChiaRequest request;
  memset(&request, 0, sizeof(request));
  request.amount = kChiaMojoPerXch;
  memset(request.parent_coin_id, 0x22, 32);
  memset(request.puzzle_hash, 0x33, 32);
  uint8_t name[32] = {};
  if (!coin_name(request, name)) { return false; }
  if (!chain_constant_time_equal(name, kExpectedCoin, 32)) {
   
    return false;
  }

  request.condition_count = 1;
  memset(request.conditions[0].puzzle_hash, 0x44, 32);
  request.conditions[0].amount = kChiaMojoPerXch;
  uint8_t solution[512] = {};
  size_t solution_size = 0;
  if (!build_solution(request, solution, sizeof(solution), &solution_size)) {
    return false;
  }
  if (solution_size != sizeof(kExpectedSolution) ||
      !chain_constant_time_equal(solution, kExpectedSolution, solution_size)) {
#if defined(HEXWALLET_HOST_TEST)
   
    for (size_t i = 0; i < solution_size; ++i) ::printf("%02x", solution[i]);
    ::printf("\n");
#endif
    return false;
  }
  // The solution must parse back as a canonical CLVM tree.
  static ClvmArena arena;
  clvm_arena_init(&arena);
  uint16_t root = 0;
  if (!clvm_parse(&arena, solution, solution_size, &root)) { return false; }
  uint8_t encoded[512] = {};
  size_t encoded_size = 0;
  if (!clvm_serialize(&arena, root, encoded, sizeof(encoded), &encoded_size)) {
    return false;
  }
  if (encoded_size != solution_size ||
      !chain_constant_time_equal(encoded, solution, solution_size)) {
    return false;
  }
  // AGG_SIG_ME oracle from blspy: the signed message is
  // condition_data || coin_name || genesis_challenge, raw and unhashed.
  static const uint8_t kExpectedMessage[96] = {
      0x55, 0xe2, 0xcb, 0x15, 0xca, 0xa7, 0xa9, 0xbd, 0x15, 0xfa, 0x5f, 0x4c,
      0xeb, 0x6e, 0x56, 0xc1, 0xdf, 0x3d, 0x9a, 0x53, 0x2e, 0xab, 0x0b, 0x36,
      0x21, 0x16, 0x23, 0x1b, 0x01, 0x73, 0xab, 0x05, 0x31, 0xe5, 0x9c, 0x4f,
      0xe2, 0x9f, 0x6f, 0x38, 0x37, 0x69, 0xbe, 0xfb, 0x41, 0x83, 0x25, 0x41,
      0x80, 0x88, 0x00, 0xd3, 0xfd, 0x4a, 0xa3, 0x46, 0x1a, 0xf7, 0xc7, 0x3d,
      0xbf, 0x8c, 0x5c, 0x93, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
      0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
      0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55
};
  static const uint8_t kExpectedSignature[96] = {
      0xa1, 0x9b, 0x7c, 0x8e, 0xaa, 0x99, 0x79, 0x23, 0x42, 0xa6, 0xa2, 0x72,
      0x39, 0x33, 0xf5, 0x2f, 0x68, 0x68, 0x08, 0xa0, 0x79, 0x93, 0xcb, 0x21,
      0xe0, 0xd8, 0x8d, 0x3d, 0x35, 0xe4, 0xff, 0xc0, 0xbd, 0xe1, 0xd8, 0xb4,
      0x3f, 0x88, 0x17, 0x22, 0x14, 0x15, 0x57, 0x43, 0x3a, 0x2d, 0xbe, 0x12,
      0x17, 0x78, 0xa4, 0x6a, 0xb0, 0xa9, 0x3a, 0xbb, 0xf5, 0xae, 0x7b, 0x0a,
      0x26, 0xe6, 0xc6, 0xeb, 0xb6, 0x26, 0x2e, 0x19, 0xda, 0x5c, 0x5f, 0xd3,
      0x2b, 0xcf, 0xf1, 0xc6, 0x27, 0xd3, 0xde, 0xec, 0x91, 0xeb, 0x30, 0x82,
      0x66, 0xe4, 0x16, 0x2b, 0x7c, 0xff, 0x2e, 0x2c, 0xb8, 0x3e, 0x8d, 0x63
};

  memset(request.genesis_challenge, 0x55, 32);
  memcpy(request.hidden_puzzle_hash, hidden, sizeof(hidden));
  uint8_t message[96] = {};
  if (!agg_sig_message(request, message)) { return false; }
  if (!chain_constant_time_equal(message, kExpectedMessage, sizeof(message))) {
    return false;
  }
  uint8_t unit_key[32] = {};
  unit_key[31] = 1;
  uint8_t secret[32] = {};
  if (!synthetic_key(unit_key, request, secret)) { return false; }
  uint8_t signature[96] = {};
  if (!bls12_381_g2_sign_augmented(secret, message, sizeof(message), signature)) {
    return false;
  }
  secure_zero(secret, sizeof(secret));
  if (!chain_constant_time_equal(signature, kExpectedSignature,
                                 sizeof(signature))) {
    return false;
  }

  // The review path must refuse a reveal that does not hash to the coin's
  // puzzle hash, and must refuse opcodes other than CREATE_COIN.
  uint8_t payload[256] = {};
  memcpy(payload, "XCH1", 4);
  payload[4] = 0;
  memset(payload + 5, 0x55, 32);    // genesis challenge
  memcpy(payload + 37, hidden, 32); // hidden puzzle hash
  memset(payload + 69, 0x22, 32);   // parent coin id
  memset(payload + 101, 0x33, 32);  // puzzle hash
  {
    uint64_t amount = kChiaMojoPerXch;
    for (size_t i = 0; i < 8; ++i) {
      payload[133 + i] = static_cast<uint8_t>((amount >> (8 * (7 - i))) & 0xff);
    }
  }
  payload[141] = 0x01;  // reveal size = 1 byte
  payload[142] = 0x00;
  payload[143] = 0x80;  // reveal = nil, whose tree hash is not the puzzle hash
  payload[144] = 0x01;  // one condition
  payload[145] = 0x33;  // CREATE_COIN
  memset(payload + 146, 0x44, 32);
  {
    uint64_t amount = kChiaMojoPerXch;
    for (size_t i = 0; i < 8; ++i) {
      payload[178 + i] = static_cast<uint8_t>((amount >> (8 * (7 - i))) & 0xff);
    }
  }
  const size_t payload_size = 186;
  ChainReview review;
  uint8_t digest[32] = {};
  if (chia_review_payload(payload, payload_size, "xch-test", &review, digest) ==
      ChainError::Ok) {
    return false;  // the nil reveal cannot match a 0x33.. puzzle hash
  }

  // Positive end-to-end path: reveal = nil, whose tree hash is the canonical
  // CLVM nil hash, so the coin's puzzle hash is kNilHash. Coin, address and
  // signature below were produced independently with blspy/bech32m.
  static const uint8_t kNilHash[32] = {
      0x4b, 0xf5, 0x12, 0x2f, 0x34, 0x45, 0x54, 0xc5, 0x3b, 0xde, 0x2e,
      0xbb, 0x8c, 0xd2, 0xb7, 0xe3, 0xd1, 0x60, 0x0a, 0xd6, 0x31, 0xc3,
      0x85, 0xa5, 0xd7, 0xcc, 0xe2, 0x3c, 0x77, 0x85, 0x45, 0x9a};
  static const char kExpectedAddress[] =
      "xch1g3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zqvvpens";
  static const uint8_t kExpectedDigest[32] = {
      0x22, 0x7e, 0x88, 0x66, 0x23, 0x9a, 0x53, 0xc9, 0xfa, 0x23, 0xd8, 0xe9,
      0x8f, 0x6e, 0x29, 0x24, 0xbc, 0x26, 0xed, 0xca, 0x1e, 0x46, 0xf0, 0x45,
      0x3c, 0xa4, 0x2d, 0x8f, 0xbc, 0x87, 0x3f, 0xc7
};
  static const uint8_t kExpectedPaymentCoin[32] = {
      0xb2, 0xb0, 0x71, 0x25, 0x8c, 0x1d, 0xe8, 0x21, 0xf5, 0xc4, 0xb3,
      0xf6, 0xef, 0x18, 0xb9, 0x97, 0x38, 0x70, 0xf3, 0x93, 0x8b, 0x8f,
      0xd4, 0x88, 0x83, 0x5a, 0x32, 0x3d, 0x9e, 0x05, 0x5e, 0x77};
  static const uint8_t kExpectedPaymentSignature[96] = {
      0xac, 0xf4, 0x91, 0xa5, 0xba, 0x7e, 0x42, 0x2e, 0xdf, 0xb4, 0x19, 0xae,
      0xeb, 0xcf, 0xd1, 0x70, 0x8b, 0xce, 0x94, 0x0b, 0xb3, 0x0f, 0xba, 0x37,
      0x05, 0x4d, 0x36, 0x78, 0x8c, 0x9a, 0xbb, 0x99, 0xa8, 0x22, 0x20, 0x3d,
      0x1a, 0xda, 0x0e, 0x51, 0xe1, 0xee, 0x49, 0xeb, 0x4d, 0x2c, 0x1c, 0x9a,
      0x02, 0x2e, 0xe0, 0xea, 0xe8, 0x29, 0x7f, 0x9b, 0x25, 0x79, 0x3d, 0x3e,
      0xaf, 0xb6, 0x46, 0xb3, 0xdd, 0xae, 0xca, 0x3e, 0x1b, 0xa4, 0x70, 0x9f,
      0xd5, 0xeb, 0xf3, 0x6d, 0xc1, 0x1c, 0x13, 0x42, 0x49, 0x9f, 0xc1, 0xca,
      0x7a, 0xfb, 0xce, 0x04, 0xe2, 0x77, 0x96, 0x26, 0x5f, 0xc0, 0xc4, 0x3b
};

  memcpy(payload + 101, kNilHash, 32);
  ChainReview payment_review;
  uint8_t payment_digest[32] = {};
  if (chia_review_payload(payload, payload_size, "xch-test", &payment_review,
                          payment_digest) != ChainError::Ok) {
    return false;
  }
  if (strcmp(payment_review.recipient, kExpectedAddress) != 0 ||
      !chain_constant_time_equal(payment_digest, kExpectedDigest, 32)) {
    return false;
  }
  uint8_t signed_out[1024] = {};
  size_t signed_size = sizeof(signed_out);
  if (chia_sign_payload(payload, payload_size, unit_key, signed_out,
                        &signed_size) != ChainError::Ok) {
    return false;
  }
  if (signed_size != kChiaSignatureSize + 32 + 2 + sizeof(kExpectedSolution) ||
      !chain_constant_time_equal(signed_out, kExpectedPaymentSignature,
                                 kChiaSignatureSize) ||
      !chain_constant_time_equal(signed_out + kChiaSignatureSize,
                                 kExpectedPaymentCoin, 32)) {
    return false;
  }
  return true;
}

} // namespace hexwallet
