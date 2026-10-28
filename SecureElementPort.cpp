#include "SecureElementPort.h"

#include <string.h>

#include "WalletSecurity.h"

namespace hexwallet {
namespace {

// ---------------------------------------------------------------------------
// AES tables
// ---------------------------------------------------------------------------

constexpr uint8_t gf_mul8(uint8_t a, uint8_t b) {
  uint8_t product = 0;
  for (int bit = 0; bit < 8; ++bit) {
    if ((b & 0x01U) != 0) product = static_cast<uint8_t>(product ^ a);
    const bool carry = (a & 0x80U) != 0;
    a = static_cast<uint8_t>(a << 1);
    if (carry) a = static_cast<uint8_t>(a ^ 0x1bU);
    b = static_cast<uint8_t>(b >> 1);
  }
  return product;
}

// Multiplicative inverse in GF(2^8) mod x^8+x^4+x^3+x+1 by square-and-multiply.
constexpr uint8_t gf_inv8(uint8_t value) {
  if (value == 0) return 0;
  uint8_t result = 1;
  uint8_t base = value;
  unsigned exponent = 254;
  while (exponent != 0) {
    if ((exponent & 1U) != 0) result = gf_mul8(result, base);
    base = gf_mul8(base, base);
    exponent >>= 1;
  }
  return result;
}

constexpr uint8_t rotl8(uint8_t value, unsigned count) {
  return static_cast<uint8_t>((value << count) | (value >> (8 - count)));
}

struct AesTables {
  uint8_t sbox[256];
};

// FIPS-197 S-box: multiplicative inverse followed by the affine transform.
constexpr AesTables make_aes_tables() {
  AesTables tables{};
  for (int index = 0; index < 256; ++index) {
    const uint8_t inverse = gf_inv8(static_cast<uint8_t>(index));
    uint8_t value = inverse;
    for (unsigned shift = 1; shift <= 4; ++shift) {
      value = static_cast<uint8_t>(value ^ rotl8(inverse, shift));
    }
    tables.sbox[index] = static_cast<uint8_t>(value ^ 0x63U);
  }
  return tables;
}

constexpr AesTables kAesTables = make_aes_tables();

void add_round_key(uint8_t state[16], const uint8_t *round_key) {
  for (size_t index = 0; index < 16; ++index) {
    state[index] = static_cast<uint8_t>(state[index] ^ round_key[index]);
  }
}

void sub_bytes(uint8_t state[16]) {
  for (size_t index = 0; index < 16; ++index) {
    state[index] = kAesTables.sbox[state[index]];
  }
}

// Row r of the column-major state is rotated left by r positions.
void shift_rows(uint8_t state[16]) {
  uint8_t shifted[16];
  for (size_t column = 0; column < 4; ++column) {
    for (size_t row = 0; row < 4; ++row) {
      shifted[column * 4 + row] = state[((column + row) % 4) * 4 + row];
    }
  }
  memcpy(state, shifted, sizeof(shifted));
}

void mix_columns(uint8_t state[16]) {
  for (size_t column = 0; column < 4; ++column) {
    uint8_t *block = state + column * 4;
    const uint8_t a0 = block[0], a1 = block[1], a2 = block[2], a3 = block[3];
    const uint8_t x0 = gf_mul8(a0, 2), x1 = gf_mul8(a1, 2);
    const uint8_t x2 = gf_mul8(a2, 2), x3 = gf_mul8(a3, 2);
    block[0] = static_cast<uint8_t>(x0 ^ x1 ^ a1 ^ a2 ^ a3);
    block[1] = static_cast<uint8_t>(a0 ^ x1 ^ x2 ^ a2 ^ a3);
    block[2] = static_cast<uint8_t>(a0 ^ a1 ^ x2 ^ x3 ^ a3);
    block[3] = static_cast<uint8_t>(x0 ^ a0 ^ a1 ^ a2 ^ x3);
  }
}

// Doubles a 128-bit CMAC subkey modulo x^128+x^7+x^2+x+1.
void cmac_double(const uint8_t in[16], uint8_t out[16]) {
  const bool high_bit = (in[0] & 0x80U) != 0;
  uint8_t carry = 0;
  for (int index = 15; index >= 0; --index) {
    const uint8_t next = static_cast<uint8_t>(in[index] & 0x80U);
    out[index] = static_cast<uint8_t>((in[index] << 1) | carry);
    carry = static_cast<uint8_t>(next >> 7);
  }
  if (high_bit) out[15] = static_cast<uint8_t>(out[15] ^ 0x87U);
}

void cmac_block(const Aes128Schedule &schedule, uint8_t chaining[16],
                const uint8_t block[16]) {
  uint8_t mixed[16];
  for (size_t index = 0; index < 16; ++index) {
    mixed[index] = static_cast<uint8_t>(chaining[index] ^ block[index]);
  }
  aes128_encrypt_block(schedule, mixed, chaining);
  secure_zero(mixed, sizeof(mixed));
}

bool constant_time_equal(const uint8_t *left, const uint8_t *right, size_t size) {
  uint8_t difference = 0;
  for (size_t index = 0; index < size; ++index) {
    difference = static_cast<uint8_t>(difference | (left[index] ^ right[index]));
  }
  return difference == 0;
}

bool hex_equals(const uint8_t *value, size_t size, const char *hex) {
  static const char kHex[] = "0123456789abcdef";
  for (size_t index = 0; index < size; ++index) {
    if (hex[index * 2] != kHex[value[index] >> 4] ||
        hex[index * 2 + 1] != kHex[value[index] & 0x0F]) {
      return false;
    }
  }
  return hex[size * 2] == '\0';
}

// The single backend a build links. Nothing is registered by default.
const SecureElementBackend *g_backend = nullptr;
bool g_open = false;

}  // namespace

uint16_t iso7816_crc16(const uint8_t *data, size_t size) {
  uint16_t crc = 0xFFFF;
  if (data == nullptr) return crc;
  for (size_t index = 0; index < size; ++index) {
    crc = static_cast<uint16_t>(crc ^ (static_cast<uint16_t>(data[index]) << 8));
    for (int bit = 0; bit < 8; ++bit) {
      crc = (crc & 0x8000U) != 0 ? static_cast<uint16_t>((crc << 1) ^ 0x1021U)
                                 : static_cast<uint16_t>(crc << 1);
    }
  }
  return crc;
}

void aes128_expand_key(const uint8_t key[16], Aes128Schedule *schedule) {
  if (schedule == nullptr) return;
  if (key == nullptr) {
    secure_zero(schedule, sizeof(*schedule));
    return;
  }
  memcpy(schedule->round_keys, key, 16);
  uint8_t round_constant = 1;
  for (size_t offset = 16; offset < sizeof(schedule->round_keys); offset += 4) {
    uint8_t word[4];
    memcpy(word, schedule->round_keys + offset - 4, sizeof(word));
    if (offset % 16 == 0) {
      const uint8_t first = word[0];
      word[0] = static_cast<uint8_t>(kAesTables.sbox[word[1]] ^ round_constant);
      word[1] = kAesTables.sbox[word[2]];
      word[2] = kAesTables.sbox[word[3]];
      word[3] = kAesTables.sbox[first];
      round_constant = gf_mul8(round_constant, 2);
    }
    for (size_t index = 0; index < 4; ++index) {
      schedule->round_keys[offset + index] =
          static_cast<uint8_t>(schedule->round_keys[offset + index - 16] ^ word[index]);
    }
  }
}

void aes128_encrypt_block(const Aes128Schedule &schedule, const uint8_t in[16],
                          uint8_t out[16]) {
  if (in == nullptr || out == nullptr) return;
  uint8_t state[16];
  memcpy(state, in, sizeof(state));
  add_round_key(state, schedule.round_keys);
  for (int round = 1; round < 10; ++round) {
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(state, schedule.round_keys + round * 16);
  }
  sub_bytes(state);
  shift_rows(state);
  add_round_key(state, schedule.round_keys + 160);
  memcpy(out, state, sizeof(state));
  secure_zero(state, sizeof(state));
}

bool aes128_cmac(const uint8_t key[16], const uint8_t *data, size_t size,
                 uint8_t mac[16]) {
  if (key == nullptr || mac == nullptr || (data == nullptr && size != 0)) {
    return false;
  }
  Aes128Schedule schedule;
  aes128_expand_key(key, &schedule);
  uint8_t zero[16] = {};
  uint8_t subkey1[16];
  uint8_t subkey2[16];
  aes128_encrypt_block(schedule, zero, subkey1);
  cmac_double(subkey1, subkey1);
  cmac_double(subkey1, subkey2);

  const size_t block_count = size == 0 ? 1 : (size + 15) / 16;
  const size_t full_blocks = block_count - 1;
  uint8_t chaining[16] = {};
  for (size_t block = 0; block < full_blocks; ++block) {
    cmac_block(schedule, chaining, data + block * 16);
  }
  const size_t last_offset = full_blocks * 16;
  const size_t last_size = size - last_offset;
  uint8_t last[16] = {};
  if (last_size != 0) memcpy(last, data + last_offset, last_size);
  if (last_size == 16) {
    for (size_t index = 0; index < 16; ++index) {
      last[index] = static_cast<uint8_t>(last[index] ^ subkey1[index]);
    }
  } else {
    last[last_size] = 0x80;
    for (size_t index = 0; index < 16; ++index) {
      last[index] = static_cast<uint8_t>(last[index] ^ subkey2[index]);
    }
  }
  cmac_block(schedule, chaining, last);
  memcpy(mac, chaining, 16);
  secure_zero(&schedule, sizeof(schedule));
  secure_zero(chaining, sizeof(chaining));
  secure_zero(last, sizeof(last));
  secure_zero(subkey1, sizeof(subkey1));
  secure_zero(subkey2, sizeof(subkey2));
  return true;
}

bool secure_element_register_backend(const SecureElementBackend *backend) {
  if (backend == nullptr) {
    secure_element_close();
    g_backend = nullptr;
    return true;
  }
  if (backend->name == nullptr || backend->open == nullptr ||
      backend->session_authenticated == nullptr ||
      backend->sign_digest == nullptr || backend->public_key == nullptr ||
      backend->close == nullptr) {
    return false;
  }
  if (g_backend != nullptr) return false;
  g_backend = backend;
  g_open = false;
  return true;
}

namespace {

void set_reason(char *reason, size_t reason_size, const char *text) {
  if (reason == nullptr || reason_size == 0) return;
  const size_t length = strlen(text);
  const size_t take = length < reason_size - 1 ? length : reason_size - 1;
  memcpy(reason, text, take);
  reason[take] = '\0';
}

}  // namespace

bool secure_element_open(char *reason, size_t reason_size) {
  if (reason != nullptr && reason_size != 0) reason[0] = '\0';
  if (g_backend == nullptr) {
    set_reason(reason, reason_size, "no SE backend registered");
    return false;
  }
  if (g_open) secure_element_close();
  if (!g_backend->open(reason, reason_size)) {
    g_open = false;
    return false;
  }
  if (!g_backend->session_authenticated()) {
    // A backend that returns success without an authenticated channel cannot be
    // trusted for anything else either, so it is unregistered entirely.
    g_backend->close();
    g_open = false;
    g_backend = nullptr;
    set_reason(reason, reason_size,
               "backend claimed success without an authenticated session");
    return false;
  }
  g_open = true;
  return true;
}

bool secure_element_ready() {
  return g_backend != nullptr && g_open && g_backend->session_authenticated();
}

const char *secure_element_name() {
  return g_backend == nullptr || g_backend->name == nullptr ? "" : g_backend->name;
}

void secure_element_close() {
  if (g_backend != nullptr && g_open) g_backend->close();
  g_open = false;
}

// ---------------------------------------------------------------------------
// Self-tests
// ---------------------------------------------------------------------------

namespace {

// Two fake backends: one that opens the transport but never authenticates (the
// failure mode a real card produces when the static keys are wrong), and one
// that authenticates. Only the second may ever satisfy the custody gate.
bool g_fake_open = false;

bool fake_open_without_session(char *reason, size_t reason_size) {
  (void)reason;
  (void)reason_size;
  return true;
}

bool fake_never_authenticated() {
  return false;
}

bool fake_open_with_session(char *reason, size_t reason_size) {
  (void)reason;
  (void)reason_size;
  g_fake_open = true;
  return true;
}

bool fake_authenticated() {
  return g_fake_open;
}

bool fake_sign(uint32_t key_handle, const uint8_t digest[32], uint8_t *signature,
               size_t *signature_size) {
  (void)key_handle;
  (void)digest;
  (void)signature;
  (void)signature_size;
  return false;
}

bool fake_public_key(uint32_t key_handle, uint8_t *public_key,
                     size_t *public_key_size) {
  (void)key_handle;
  (void)public_key;
  (void)public_key_size;
  return false;
}

void fake_close() {
  g_fake_open = false;
}

const SecureElementBackend kFakeUnverified = {
    "fake-unverified", fake_open_without_session, fake_never_authenticated,
    fake_sign, fake_public_key, fake_close};
const SecureElementBackend kFakeVerified = {
    "fake-verified", fake_open_with_session, fake_authenticated, fake_sign,
    fake_public_key, fake_close};
const SecureElementBackend kFakeIncomplete = {
    "fake-incomplete", fake_open_with_session, nullptr, nullptr, nullptr,
    fake_close};

}  // namespace

bool run_secure_element_self_tests() {
  bool passed = true;

  // ISO 7816-3 CRC16/A published check value (CRC-16/CCITT-FALSE).
  static const uint8_t kCheck[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
  passed = (iso7816_crc16(kCheck, sizeof(kCheck)) == 0x29B1) && passed;
  passed = (iso7816_crc16(nullptr, 0) == 0xFFFF) && passed;

  // FIPS-197 appendix C.1: AES-128 single block.
  static const uint8_t kFipsKey[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                       0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                                       0x0e, 0x0f};
  static const uint8_t kFipsPlain[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                         0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                         0xcc, 0xdd, 0xee, 0xff};
  Aes128Schedule schedule;
  aes128_expand_key(kFipsKey, &schedule);
  uint8_t cipher[16] = {};
  aes128_encrypt_block(schedule, kFipsPlain, cipher);
  passed = hex_equals(cipher, sizeof(cipher),
                      "69c4e0d86a7b0430d8cdb78070b4c55a") && passed;
  secure_zero(&schedule, sizeof(schedule));

  // RFC 4493 section 4: AES-128-CMAC over 0, 16, 40 and 64 byte messages.
  // The 40-byte case exercises the padding path, 16 and 64 the subkey path.
  static const uint8_t kCmacKey[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2,
                                       0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
                                       0x4f, 0x3c};
  static const uint8_t kMessage64[64] = {
      0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11,
      0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
      0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46,
      0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
      0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
      0xe6, 0x6c, 0x37, 0x10};
  uint8_t mac[16] = {};
  passed = aes128_cmac(kCmacKey, nullptr, 0, mac) &&
           hex_equals(mac, sizeof(mac), "bb1d6929e95937287fa37d129b756746") &&
           passed;
  passed = aes128_cmac(kCmacKey, kMessage64, 16, mac) &&
           hex_equals(mac, sizeof(mac), "070a16b46b4d4144f79bdd9dd04a287c") &&
           passed;
  passed = aes128_cmac(kCmacKey, kMessage64, 40, mac) &&
           hex_equals(mac, sizeof(mac), "dfa66747de9ae63030ca32611497c827") &&
           passed;
  passed = aes128_cmac(kCmacKey, kMessage64, 64, mac) &&
           hex_equals(mac, sizeof(mac), "51f0bebf7e3b9d92fc49741779363cfe") &&
           passed;
  // A key-dependent MAC must not collide with a different key.
  static const uint8_t kOtherKey[16] = {0x2c, 0x7f, 0x16, 0x17, 0x29, 0xaf, 0xd3,
                                        0xa7, 0xac, 0xf8, 0x16, 0x89, 0x0a, 0xd0,
                                        0x4e, 0x3d};
  uint8_t other_mac[16] = {};
  passed = aes128_cmac(kOtherKey, kMessage64, 16, other_mac) &&
           !constant_time_equal(mac, other_mac, 16) && passed;

  // Gate behaviour: nothing registered means nothing ready.
  secure_element_register_backend(nullptr);
  char reason[96];
  passed = !secure_element_ready() && strcmp(secure_element_name(), "") == 0 && passed;
  passed = !secure_element_open(reason, sizeof(reason)) && !secure_element_ready() && passed;

  // An incomplete contract must be refused.
  passed = !secure_element_register_backend(&kFakeIncomplete) &&
           !secure_element_ready() && passed;

  // A backend that opens the transport but never authenticates must leave the
  // gate closed and must be unregistered, because a real card that rejects the
  // static keys produces exactly this answer.
  passed = secure_element_register_backend(&kFakeUnverified) && passed;
  passed = !secure_element_open(reason, sizeof(reason)) && !secure_element_ready() &&
           strcmp(secure_element_name(), "") == 0 && passed;

  // A backend with an authenticated session may satisfy the gate...
  passed = secure_element_register_backend(&kFakeVerified) && passed;
  passed = secure_element_open(reason, sizeof(reason)) && secure_element_ready() &&
           strcmp(secure_element_name(), "fake-verified") == 0 && passed;
  // ...but only one backend may be registered at a time.
  passed = !secure_element_register_backend(&kFakeVerified) && passed;
  secure_element_close();
  passed = !secure_element_ready() && passed;
  // Closing is idempotent, and removing the backend leaves nothing ready.
  secure_element_close();
  passed = secure_element_register_backend(nullptr) && !secure_element_ready() &&
           strcmp(secure_element_name(), "") == 0 && passed;

  secure_zero(reason, sizeof(reason));
  secure_zero(mac, sizeof(mac));
  secure_zero(other_mac, sizeof(other_mac));
  secure_zero(cipher, sizeof(cipher));
  return passed;
}

}  // namespace hexwallet
