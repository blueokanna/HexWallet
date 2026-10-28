#include "QrlXmss.h"

#include <string.h>

#include "CryptoPrimitives.h"

namespace hexwallet {
namespace {

constexpr size_t kN = 32;
constexpr uint32_t kWotsW = 16;
constexpr uint32_t kWotsLen1 = 64;
constexpr uint32_t kWotsLen2 = 3;
constexpr uint32_t kWotsLen = kWotsLen1 + kWotsLen2;
constexpr size_t kWotsKeySize = kWotsLen * kN;
constexpr uint8_t kMinHeight = 4;
constexpr uint8_t kMaxHeight = 12;
constexpr uint8_t kHashShake256 = 2;

struct WipeOnExit {
  void *data;
  size_t size;
  ~WipeOnExit() { secure_zero(data, size); }
};

void to_bytes_be(uint64_t value, uint8_t *out, size_t size) {
  for (size_t index = size; index != 0; --index) {
    out[index - 1] = static_cast<uint8_t>(value);
    value >>= 8;
  }
}

void addr_to_bytes(const uint32_t addr[8], uint8_t out[32]) {
  for (size_t index = 0; index < 8; ++index) {
    to_bytes_be(addr[index], out + index * 4, 4);
  }
}

void set_type(uint32_t addr[8], uint32_t type) {
  addr[3] = type;
  for (size_t index = 4; index < 8; ++index) addr[index] = 0;
}

void set_ots(uint32_t addr[8], uint32_t value) { addr[4] = value; }
void set_ltree(uint32_t addr[8], uint32_t value) { addr[4] = value; }
void set_chain(uint32_t addr[8], uint32_t value) { addr[5] = value; }
void set_hash(uint32_t addr[8], uint32_t value) { addr[6] = value; }
void set_tree_height(uint32_t addr[8], uint32_t value) { addr[5] = value; }
void set_tree_index(uint32_t addr[8], uint32_t value) { addr[6] = value; }
void set_key_and_mask(uint32_t addr[8], uint32_t value) { addr[7] = value; }

void clear_chain_hash_key(uint32_t addr[8]) {
  addr[5] = 0;
  addr[6] = 0;
  addr[7] = 0;
}

// XMSS reference core hash: SHAKE-256(toByte(type, 32) || key || input).
bool core_hash(uint32_t type, const uint8_t key[kN], const uint8_t *input,
               size_t input_size, uint8_t out[kN]) {
  if (input == nullptr || input_size > 2 * kN) return false;
  uint8_t buffer[3 * kN + kN];
  to_bytes_be(type, buffer, kN);
  if (key != nullptr) memcpy(buffer + kN, key, kN);
  else memset(buffer + kN, 0, kN);
  if (input_size != 0) memcpy(buffer + 2 * kN, input, input_size);
  const bool ok = crypto_shake256(buffer, 2 * kN + input_size, out, kN);
  secure_zero(buffer, sizeof(buffer));
  return ok;
}

bool prf(uint8_t out[kN], const uint8_t input[kN], const uint8_t key[kN]) {
  return core_hash(3, key, input, kN, out);
}

bool hash_f(uint8_t out[kN], const uint8_t input[kN],
            const uint8_t pub_seed[kN], uint32_t addr[8]) {
  uint8_t key[kN];
  uint8_t mask[kN];
  uint8_t bytes[32];
  set_key_and_mask(addr, 0);
  addr_to_bytes(addr, bytes);
  bool ok = prf(key, bytes, pub_seed);
  if (ok) {
    set_key_and_mask(addr, 1);
    addr_to_bytes(addr, bytes);
    ok = prf(mask, bytes, pub_seed);
  }
  if (!ok) {
    secure_zero(key, sizeof(key));
    secure_zero(mask, sizeof(mask));
    return false;
  }
  uint8_t masked[kN];
  for (size_t index = 0; index < kN; ++index) masked[index] = input[index] ^ mask[index];
  ok = core_hash(0, key, masked, kN, out);
  secure_zero(key, sizeof(key));
  secure_zero(mask, sizeof(mask));
  secure_zero(masked, sizeof(masked));
  return ok;
}

bool hash_h(uint8_t out[kN], const uint8_t input[2 * kN],
            const uint8_t pub_seed[kN], uint32_t addr[8]) {
  uint8_t key[kN];
  uint8_t mask[2 * kN];
  uint8_t bytes[32];
  set_key_and_mask(addr, 0);
  addr_to_bytes(addr, bytes);
  bool ok = prf(key, bytes, pub_seed);
  if (ok) {
    set_key_and_mask(addr, 1);
    addr_to_bytes(addr, bytes);
    ok = prf(mask, bytes, pub_seed);
  }
  if (ok) {
    set_key_and_mask(addr, 2);
    addr_to_bytes(addr, bytes);
    ok = prf(mask + kN, bytes, pub_seed);
  }
  if (!ok) {
    secure_zero(key, sizeof(key));
    secure_zero(mask, sizeof(mask));
    return false;
  }
  uint8_t masked[2 * kN];
  for (size_t index = 0; index < 2 * kN; ++index) masked[index] = input[index] ^ mask[index];
  ok = core_hash(1, key, masked, 2 * kN, out);
  secure_zero(key, sizeof(key));
  secure_zero(mask, sizeof(mask));
  secure_zero(masked, sizeof(masked));
  return ok;
}

bool wots_pkgen(uint8_t *public_key, const uint8_t ots_seed[kN],
                const uint8_t pub_seed[kN], uint32_t ots_addr[8]) {
  for (uint32_t chain = 0; chain < kWotsLen; ++chain) {
    uint8_t counter[32];
    memset(counter, 0, sizeof(counter));
    to_bytes_be(chain, counter, sizeof(counter));
    uint8_t *value = public_key + chain * kN;
    if (!prf(value, counter, ots_seed)) return false;
    set_chain(ots_addr, chain);
    for (uint32_t step = 0; step < kWotsW - 1; ++step) {
      set_hash(ots_addr, step);
      if (!hash_f(value, value, pub_seed, ots_addr)) return false;
    }
  }
  return true;
}

bool l_tree(uint8_t out[kN], uint8_t *public_key, const uint8_t pub_seed[kN],
            uint32_t addr[8]) {
  uint32_t count = kWotsLen;
  uint32_t height = 0;
  set_tree_height(addr, height);
  while (count > 1) {
    const uint32_t bound = count >> 1;
    for (uint32_t index = 0; index < bound; ++index) {
      set_tree_index(addr, index);
      if (!hash_h(public_key + index * kN,
                  public_key + 2 * index * kN, pub_seed, addr)) {
        return false;
      }
    }
    if ((count & 1U) != 0) {
      memcpy(public_key + bound * kN, public_key + (count - 1) * kN, kN);
    }
    count = (count + 1) >> 1;
    ++height;
    set_tree_height(addr, height);
  }
  memcpy(out, public_key, kN);
  return true;
}

int treehash(uint8_t out[kN], uint8_t height, const uint8_t sk_seed[kN],
             const uint8_t pub_seed[kN], const uint32_t root_addr[8],
             QrlProgressHook progress, void *context) {
  uint8_t stack[(kMaxHeight + 1) * kN];
  WipeOnExit wipe_stack{stack, sizeof(stack)};
  uint8_t levels[kMaxHeight + 1];
  size_t offset = 0;
  uint32_t ots_addr[8];
  uint32_t ltree_addr[8];
  uint32_t node_addr[8];
  memcpy(ots_addr, root_addr, 12);
  set_type(ots_addr, 0);
  memcpy(ltree_addr, root_addr, 12);
  set_type(ltree_addr, 1);
  memcpy(node_addr, root_addr, 12);
  set_type(node_addr, 2);

  const uint32_t leaf_count = uint32_t{1} << height;
  for (uint32_t index = 0; index < leaf_count; ++index) {
    set_ltree(ltree_addr, index);
    set_ots(ots_addr, index);
    clear_chain_hash_key(ots_addr);
    uint8_t bytes[32];
    addr_to_bytes(ots_addr, bytes);
    uint8_t ots_seed[kN];
    if (!prf(ots_seed, bytes, sk_seed)) {
      secure_zero(ots_seed, sizeof(ots_seed));
      return 0;
    }
    uint8_t wots_public[kWotsKeySize];
    const bool generated = wots_pkgen(wots_public, ots_seed, pub_seed, ots_addr) &&
                           l_tree(stack + offset * kN, wots_public, pub_seed, ltree_addr);
    secure_zero(wots_public, sizeof(wots_public));
    secure_zero(ots_seed, sizeof(ots_seed));
    if (!generated) return 0;

    levels[offset] = 0;
    ++offset;
    while (offset > 1 && levels[offset - 1] == levels[offset - 2]) {
      set_tree_height(node_addr, levels[offset - 1]);
      set_tree_index(node_addr, index >> (levels[offset - 1] + 1));
      if (!hash_h(stack + (offset - 2) * kN, stack + (offset - 2) * kN,
                  pub_seed, node_addr)) {
        return 0;
      }
      ++levels[offset - 2];
      --offset;
    }
    if (progress != nullptr && !progress(index + 1, leaf_count, context)) {
      return -1;
    }
  }
  if (offset != 1) return 0;
  memcpy(out, stack, kN);
  secure_zero(stack, sizeof(stack));
  return 1;
}

char hex_digit(uint8_t value) {
  return static_cast<char>(value < 10 ? '0' + value : 'a' + (value - 10));
}

int hex_value(char character) {
  if (character >= '0' && character <= '9') return character - '0';
  if (character >= 'a' && character <= 'f') return character - 'a' + 10;
  if (character >= 'A' && character <= 'F') return character - 'A' + 10;
  return -1;
}

uint8_t descriptor_height(uint8_t public_key_byte) {
  return static_cast<uint8_t>((public_key_byte & 0x0F) << 1);
}

bool encode_text(const uint8_t address[kQrlAddressBytes], char *out,
                 size_t out_size) {
  if (out == nullptr || out_size < kQrlAddressTextSize) return false;
  out[0] = 'Q';
  for (size_t index = 0; index < kQrlAddressBytes; ++index) {
    out[1 + index * 2] = hex_digit(address[index] >> 4);
    out[2 + index * 2] = hex_digit(address[index] & 0x0F);
  }
  out[kQrlAddressTextSize - 1] = '\0';
  return true;
}

}  // namespace

WalletError qrl_xmss_public_key_ex(const uint8_t seed[kQrlSeedSize], uint8_t height,
                                   QrlProgressHook progress, void *context,
                                   uint8_t out_public_key[kQrlPublicKeySize]) {
  if (out_public_key != nullptr) secure_zero(out_public_key, kQrlPublicKeySize);
  if (seed == nullptr || out_public_key == nullptr || height < kMinHeight ||
      height > kMaxHeight || (height & 1U) != 0) {
    return WalletError::InvalidArgument;
  }
  uint8_t expanded[3 * kN];
  WipeOnExit wipe_expanded{expanded, sizeof(expanded)};
  if (!crypto_shake256(seed, kQrlSeedSize, expanded, sizeof(expanded))) {
    return WalletError::CryptoFailure;
  }
  const uint8_t *sk_seed = expanded;
  const uint8_t *pub_seed = expanded + 2 * kN;
  uint8_t root[kN];
  uint32_t root_addr[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
  const int status = treehash(root, height, sk_seed, pub_seed, root_addr, progress, context);
  if (status == 1) {
    out_public_key[0] = kHashShake256;
    out_public_key[1] = static_cast<uint8_t>(height >> 1);
    out_public_key[2] = 0;
    memcpy(out_public_key + 3, root, kN);
    memcpy(out_public_key + 3 + kN, pub_seed, kN);
  }
  secure_zero(expanded, sizeof(expanded));
  secure_zero(root, sizeof(root));
  if (status == 1) return WalletError::Ok;
  secure_zero(out_public_key, kQrlPublicKeySize);
  return status < 0 ? WalletError::Aborted : WalletError::CryptoFailure;
}

WalletError qrl_xmss_public_key(const uint8_t seed[kQrlSeedSize], uint8_t height,
                                uint8_t out_public_key[kQrlPublicKeySize]) {
  return qrl_xmss_public_key_ex(seed, height, nullptr, nullptr, out_public_key);
}

WalletError qrl_address_from_public_key(
  const uint8_t public_key[kQrlPublicKeySize], char *out, size_t out_size) {
  if (out != nullptr && out_size != 0) out[0] = '\0';
  if (public_key == nullptr || out == nullptr || out_size < kQrlAddressTextSize) {
    return WalletError::InvalidArgument;
  }
  const uint8_t height = descriptor_height(public_key[1]);
  if ((public_key[0] & 0x0F) != kHashShake256 ||
      ((public_key[0] >> 4) & 0x0F) != 0 || (public_key[1] >> 4) != 0 ||
      public_key[2] != 0 || height < kMinHeight || height > kMaxHeight ||
      (height & 1U) != 0) {
    return WalletError::InvalidArgument;
  }
  uint8_t address[kQrlAddressBytes];
  memcpy(address, public_key, 3);
  uint8_t hashed[kSha256Size];
  uint8_t checksum[kSha256Size];
  bool ok = crypto_sha256(public_key, kQrlPublicKeySize, hashed);
  if (ok) {
    memcpy(address + 3, hashed, kN);
    ok = crypto_sha256(address, 3 + kN, checksum);
  }
  if (ok) {
    memcpy(address + 3 + kN, checksum + kSha256Size - 4, 4);
    ok = encode_text(address, out, out_size);
  }
  secure_zero(hashed, sizeof(hashed));
  secure_zero(checksum, sizeof(checksum));
  secure_zero(address, sizeof(address));
  return ok ? WalletError::Ok : WalletError::CryptoFailure;
}

WalletError qrl_xmss_address_ex(const uint8_t seed[kQrlSeedSize], uint8_t height,
                                QrlProgressHook progress, void *context,
                                char *out, size_t out_size) {
  if (out != nullptr && out_size != 0) out[0] = '\0';
  if (out == nullptr || out_size < kQrlAddressTextSize) {
    return WalletError::InvalidArgument;
  }
  uint8_t public_key[kQrlPublicKeySize];
  WipeOnExit wipe_public{public_key, sizeof(public_key)};
  const WalletError result = qrl_xmss_public_key_ex(seed, height, progress, context, public_key);
  if (result != WalletError::Ok) return result;
  const WalletError encoded = qrl_address_from_public_key(public_key, out, out_size);
  secure_zero(public_key, sizeof(public_key));
  return encoded;
}

WalletError qrl_xmss_address(const uint8_t seed[kQrlSeedSize], uint8_t height,
                             char *out, size_t out_size) {
  return qrl_xmss_address_ex(seed, height, nullptr, nullptr, out, out_size);
}

WalletError qrl_seed_from_bip39(const uint8_t bip39_seed[kSeedSize],
                                uint32_t address_index,
                                uint8_t out_seed[kQrlSeedSize]) {
  if (out_seed != nullptr) secure_zero(out_seed, kQrlSeedSize);
  if (bip39_seed == nullptr || out_seed == nullptr) return WalletError::InvalidArgument;
  // Preserve the original wallet's index-zero tree for recovery. Older builds
  // ignored every index; their nonzero paths also refer to this legacy tree.
  if (address_index == 0) {
    static const char legacy_domain[] = "HexWallet/QRL/v1";
    uint8_t legacy[sizeof(legacy_domain) - 1 + kSeedSize];
    memcpy(legacy, legacy_domain, sizeof(legacy_domain) - 1);
    memcpy(legacy + sizeof(legacy_domain) - 1, bip39_seed, kSeedSize);
    const bool ok = crypto_shake256(legacy, sizeof(legacy), out_seed, kQrlSeedSize);
    secure_zero(legacy, sizeof(legacy));
    if (!ok) secure_zero(out_seed, kQrlSeedSize);
    return ok ? WalletError::Ok : WalletError::CryptoFailure;
  }
  static const char kDomain[] = "HexWallet/QRL/v2";
  constexpr size_t kDomainSize = sizeof(kDomain) - 1;
  uint8_t buffer[kDomainSize + 4 + kSeedSize];
  memcpy(buffer, kDomain, kDomainSize);
  to_bytes_be(address_index, buffer + kDomainSize, 4);
  memcpy(buffer + kDomainSize + 4, bip39_seed, kSeedSize);
  const bool ok = crypto_shake256(buffer, sizeof(buffer), out_seed, kQrlSeedSize);
  secure_zero(buffer, sizeof(buffer));
  if (!ok) secure_zero(out_seed, kQrlSeedSize);
  return ok ? WalletError::Ok : WalletError::CryptoFailure;
}

bool qrl_address_validate(const char *address) {
  if (address == nullptr || strlen(address) != kQrlAddressTextSize - 1 ||
      (address[0] != 'Q' && address[0] != 'q')) {
    return false;
  }
  uint8_t bytes[kQrlAddressBytes];
  for (size_t index = 0; index < kQrlAddressBytes; ++index) {
    const int high = hex_value(address[1 + index * 2]);
    const int low = hex_value(address[2 + index * 2]);
    if (high < 0 || low < 0) return false;
    bytes[index] = static_cast<uint8_t>((high << 4) | low);
  }
  const uint8_t height = descriptor_height(bytes[1]);
  bool valid = (bytes[0] & 0x0F) == kHashShake256 &&
               ((bytes[0] >> 4) & 0x0F) == 0 && bytes[2] == 0 &&
               (bytes[1] >> 4) == 0 && height >= kMinHeight &&
               height <= kMaxHeight && (height & 1U) == 0;
  if (valid) {
    uint8_t checksum[kSha256Size];
    valid = crypto_sha256(bytes, 3 + kN, checksum) &&
            crypto_constant_time_equal(bytes + 3 + kN, checksum + kSha256Size - 4, 4);
    secure_zero(checksum, sizeof(checksum));
  }
  secure_zero(bytes, sizeof(bytes));
  return valid;
}

size_t qrl_xmss_signature_size(uint8_t height) {
  if (height < kMinHeight || height > kMaxHeight || (height & 1U) != 0) return 0;
  return 4 + kN + kWotsLen * kN + static_cast<size_t>(height) * kN;
}

uint32_t qrl_xmss_leaf_count(uint8_t height) {
  if (height < kMinHeight || height > kMaxHeight || (height & 1U) != 0) return 0;
  return static_cast<uint32_t>(1) << height;
}

bool qrl_ots_index_usable(uint8_t height, uint32_t burned_high_water,
                          uint32_t candidate) {
  const uint32_t leaves = qrl_xmss_leaf_count(height);
  if (leaves == 0 || candidate >= leaves) return false;
  // A candidate below the durable high-water mark is a reuse attempt; skipped
  // indices above it stay burned because the mark only moves forward.
  return candidate >= burned_high_water;
}

bool qrl_ots_next_high_water(uint8_t height, uint32_t burned_high_water,
                             uint32_t candidate, uint32_t *next_high_water) {
  if (next_high_water == nullptr) return false;
  *next_high_water = 0;
  if (!qrl_ots_index_usable(height, burned_high_water, candidate)) return false;
  const uint32_t advanced = candidate + 1;
  *next_high_water =
    advanced > burned_high_water ? advanced : burned_high_water;
  return true;
}

bool run_qrl_xmss_self_tests() {
  // qrllib tests/cpp/qrl/xmssBasicSHAKE256_test.cpp: 48 zero bytes, height 4.
  static const char kExpected[] =
    "Q0202000f9ec8efa448051a110686084a47b3ff2c497067edd68b91f36f18c1d7a78498e49b0750";
  uint8_t seed[kQrlSeedSize] = {};
  char address[kQrlAddressTextSize];
  bool passed = qrl_xmss_address(seed, 4, address, sizeof(address)) == WalletError::Ok &&
                strcmp(address, kExpected) == 0 && qrl_address_validate(address);
  if (passed) {
    address[10] = address[10] == '0' ? '1' : '0';
    passed = !qrl_address_validate(address);
  }
  uint8_t bad_seed[kQrlSeedSize] = {};
  passed = passed && qrl_xmss_public_key(bad_seed, 5, nullptr) == WalletError::InvalidArgument;
  uint8_t public_key[kQrlPublicKeySize];
  passed = passed && qrl_xmss_public_key(bad_seed, 3, public_key) == WalletError::InvalidArgument;
  passed = passed && qrl_xmss_public_key(bad_seed, 14, public_key) == WalletError::InvalidArgument;
  uint8_t bip39[kSeedSize] = {};
  uint8_t qrl_seed[kQrlSeedSize];
  passed = passed && qrl_seed_from_bip39(bip39, 0, qrl_seed) == WalletError::Ok;
  // Address indices must produce distinct keys: v1 folded no index into the
  // domain separator and every index returned the same address.
  uint8_t indexed[kQrlSeedSize];
  passed = passed &&
           qrl_seed_from_bip39(bip39, 1, indexed) == WalletError::Ok &&
           !crypto_constant_time_equal(qrl_seed, indexed, kQrlSeedSize) &&
           qrl_seed_from_bip39(bip39, 0, nullptr) ==
               WalletError::InvalidArgument;
  if (passed) {
    char address_zero[kQrlAddressTextSize];
    char address_one[kQrlAddressTextSize];
    passed = qrl_xmss_address(qrl_seed, 4, address_zero, sizeof(address_zero)) ==
                 WalletError::Ok &&
             qrl_xmss_address(indexed, 4, address_one, sizeof(address_one)) ==
                 WalletError::Ok &&
             strcmp(address_zero, address_one) != 0;
    secure_zero(address_zero, sizeof(address_zero));
    secure_zero(address_one, sizeof(address_one));
  }
  secure_zero(indexed, sizeof(indexed));
  secure_zero(qrl_seed, sizeof(qrl_seed));

  // qrllib tests/cpp/qrl/xmssBasicSHAKE256_test.cpp (SignatureLen): 2308 at
  // height 4 and 2372 at height 6 for 67 WOTS+ chains of 32 bytes.
  passed = passed && qrl_xmss_signature_size(4) == 2308 &&
           qrl_xmss_signature_size(6) == 2372 &&
           qrl_xmss_signature_size(10) == 2500 &&
           qrl_xmss_signature_size(3) == 0 &&
           qrl_xmss_signature_size(5) == 0 &&
           qrl_xmss_signature_size(14) == 0;
  passed = passed && qrl_xmss_leaf_count(4) == 16 &&
           qrl_xmss_leaf_count(10) == 1024 &&
           qrl_xmss_leaf_count(12) == 4096 &&
           qrl_xmss_leaf_count(5) == 0;

  // One-time-signature index ledger (RFC 8391 4.1.9 / 4.1.12).
  uint32_t next = 0;
  passed = passed && qrl_ots_index_usable(4, 0, 0) &&
           qrl_ots_next_high_water(4, 0, 0, &next) && next == 1 &&
           qrl_ots_index_usable(4, 0, 15) &&
           qrl_ots_next_high_water(4, 0, 15, &next) && next == 16 &&
           !qrl_ots_index_usable(4, 6, 5) &&
           !qrl_ots_index_usable(4, 0, 16) &&
           !qrl_ots_next_high_water(4, 6, 5, &next) && next == 0 &&
           !qrl_ots_next_high_water(4, 0, 16, &next) &&
           !qrl_ots_next_high_water(5, 0, 0, &next) &&
           !qrl_ots_next_high_water(4, 0, 0, nullptr);
  // A skipped index burns everything below it; the mark never moves backwards.
  passed = passed && qrl_ots_index_usable(12, 7, 4095) &&
           qrl_ots_next_high_water(12, 7, 4095, &next) && next == 4096 &&
           qrl_ots_next_high_water(12, 7, 9, &next) && next == 10 &&
           !qrl_ots_index_usable(12, 7, 4096) &&
           !qrl_ots_index_usable(12, 4096, 4095);

  secure_zero(public_key, sizeof(public_key));
  secure_zero(address, sizeof(address));
  secure_zero(seed, sizeof(seed));
  return passed;
}

}  // namespace hexwallet
