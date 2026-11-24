#include "WalletKeyBackup.h"
#include "CryptoPrimitives.h"
#include "SensitiveValue.h"
#include "UnicodeNormalizer.h"
#include "base58.h"
#include <mbedtls/aes.h>
#include <mbedtls/bignum.h>
#include <stdlib.h>
#include <string.h>
#ifdef ARDUINO_ARCH_ESP32
#include <sdkconfig.h>
#endif
#if defined(ARDUINO_ARCH_ESP32) && defined(CONFIG_IDF_TARGET_ESP32P4)
#include <esp_heap_caps.h>
#endif

namespace hexwallet {
#ifdef HEXWALLET_TEST_BACKUP_HEAP
void *backup_probe_alloc(size_t size);
void backup_probe_free(void *data, size_t size);
#endif
namespace {
class SecretHeap {
 public:
  explicit SecretHeap(size_t size) : size_(size) {
#if defined(ARDUINO_ARCH_ESP32) && defined(CONFIG_IDF_TARGET_ESP32P4)
    data_ = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
#elif defined(HEXWALLET_TEST_BACKUP_HEAP)
    data_ = backup_probe_alloc(size);
#else
    data_ = malloc(size);
#endif
  }
  ~SecretHeap() {
    if (!data_) return;
    secure_zero(data_, size_);
#ifdef HEXWALLET_TEST_BACKUP_HEAP
    backup_probe_free(data_, size_);
#else
    free(data_);
#endif
  }
  SecretHeap(const SecretHeap &) = delete;
  SecretHeap &operator=(const SecretHeap &) = delete;
  uint8_t *bytes() { return static_cast<uint8_t *>(data_); }
 private:
  void *data_;
  size_t size_;
};
bool valid_network(BitcoinKeyNetwork network) {
  return network == BitcoinKeyNetwork::Mainnet || network == BitcoinKeyNetwork::Testnet;
}
bool valid_scalar(const uint8_t *key) {
  static const uint8_t order[32] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
    0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41};
  uint8_t any = 0;
  for (size_t i = 0; i < 32; ++i) any |= key[i];
  return any && memcmp(key, order, 32) < 0;
}
int nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
WalletError checked_decode(const char *text, size_t length, uint8_t *out, size_t *size) {
  if (!b58dec(out, size, text, length) || *size < 5) return WalletError::UnsupportedFormat;
  uint8_t hash[32];
  if (!crypto_double_sha256(out, *size - 4, hash)) return WalletError::CryptoFailure;
  const bool valid = crypto_constant_time_equal(hash, out + *size - 4, 4);
  secure_zero(hash, sizeof(hash));
  if (!valid) return WalletError::InvalidChecksum;
  *size -= 4;
  return WalletError::Ok;
}
WalletError checked_encode(uint8_t *payload, size_t size, char *out, size_t capacity) {
  SensitiveValue<uint8_t[32]> hash;
  if (!crypto_double_sha256(payload, size, hash.get())) return WalletError::CryptoFailure;
  memcpy(payload + size, hash.get(), 4);
  return b58enc(out, &capacity, payload, size + 4) ? WalletError::Ok : WalletError::BufferTooSmall;
}
uint32_t read32(const uint8_t *p) {
  return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
void write32(uint8_t *p, uint32_t x) {
  for (unsigned i = 0; i < 4; ++i) p[i] = static_cast<uint8_t>(x >> (8 * i));
}
uint32_t rotl(uint32_t x, unsigned n) { return (x << n) | (x >> (32 - n)); }
void salsa8(uint32_t b[16]) {
  uint32_t x[16];
  memcpy(x, b, sizeof(x));
  for (unsigned i = 0; i < 8; i += 2) {
    x[4]^=rotl(x[0]+x[12],7); x[8]^=rotl(x[4]+x[0],9); x[12]^=rotl(x[8]+x[4],13); x[0]^=rotl(x[12]+x[8],18);
    x[9]^=rotl(x[5]+x[1],7); x[13]^=rotl(x[9]+x[5],9); x[1]^=rotl(x[13]+x[9],13); x[5]^=rotl(x[1]+x[13],18);
    x[14]^=rotl(x[10]+x[6],7); x[2]^=rotl(x[14]+x[10],9); x[6]^=rotl(x[2]+x[14],13); x[10]^=rotl(x[6]+x[2],18);
    x[3]^=rotl(x[15]+x[11],7); x[7]^=rotl(x[3]+x[15],9); x[11]^=rotl(x[7]+x[3],13); x[15]^=rotl(x[11]+x[7],18);
    x[1]^=rotl(x[0]+x[3],7); x[2]^=rotl(x[1]+x[0],9); x[3]^=rotl(x[2]+x[1],13); x[0]^=rotl(x[3]+x[2],18);
    x[6]^=rotl(x[5]+x[4],7); x[7]^=rotl(x[6]+x[5],9); x[4]^=rotl(x[7]+x[6],13); x[5]^=rotl(x[4]+x[7],18);
    x[11]^=rotl(x[10]+x[9],7); x[8]^=rotl(x[11]+x[10],9); x[9]^=rotl(x[8]+x[11],13); x[10]^=rotl(x[9]+x[8],18);
    x[12]^=rotl(x[15]+x[14],7); x[13]^=rotl(x[12]+x[15],9); x[14]^=rotl(x[13]+x[12],13); x[15]^=rotl(x[14]+x[13],18);
  }
  for (unsigned i = 0; i < 16; ++i) b[i] += x[i];
  secure_zero(x, sizeof(x));
}
void blockmix(uint32_t *x, uint32_t *y, unsigned r) {
  uint32_t t[16];
  memcpy(t, x + (2 * r - 1) * 16, sizeof(t));
  for (unsigned i = 0; i < 2 * r; ++i) {
    for (unsigned j = 0; j < 16; ++j) t[j] ^= x[i * 16 + j];
    salsa8(t);
    memcpy(y + (i / 2 + (i & 1) * r) * 16, t, sizeof(t));
  }
  memcpy(x, y, 128 * r);
  secure_zero(t, sizeof(t));
}
// Only the two parameter sets specified by BIP38 are admitted. Neither memory
// cost nor iteration count is read from the encrypted input.
WalletError scrypt(const uint8_t *password, size_t password_size, const uint8_t *salt,
                   size_t salt_size, unsigned n, unsigned r, unsigned p,
                   uint8_t *out, size_t out_size, KeyBackupControl control) {
  if (!((n == 16384 && r == 8 && p == 8) || (n == 1024 && r == 1 && p == 1)))
    return WalletError::InvalidArgument;
  if (control.progress && !control.progress(control.context)) return WalletError::Aborted;
  const size_t block_bytes = 128 * r, words = block_bytes / 4;
  // Store every fourth ROMix state in the large table. Each omitted state
  // is recovered with at most three BlockMix calls. N, r, p and the derived
  // bytes stay exactly as specified, with a 4 MiB table on the large pass.
  const unsigned spacing = n == 16384 ? 4 : 1;
  const unsigned entries = n / spacing;
  SecretHeap heap(block_bytes * (entries + p + 3));
  auto *b = heap.bytes();
  if (!b) return WalletError::OutOfMemory;
  auto *v = reinterpret_cast<uint32_t *>(b + block_bytes * p);
  auto *x = v + entries * words;
  auto *y = x + words;
  auto *checkpoint = y + words;
  if (!crypto_pbkdf2_sha256(password, password_size, salt, salt_size, 1, b, p * block_bytes))
    return WalletError::CryptoFailure;
  for (unsigned lane = 0; lane < p; ++lane) {
    for (size_t j = 0; j < words; ++j) x[j] = read32(b + lane * block_bytes + 4 * j);
    for (unsigned i = 0; i < n; ++i) {
      if (i % spacing == 0) memcpy(v + (i / spacing) * words, x, block_bytes);
      blockmix(x, y, r);
      if (!(i & 255) && control.progress && !control.progress(control.context)) return WalletError::Aborted;
    }
    for (unsigned i = 0; i < n; ++i) {
      const size_t j = x[(2 * r - 1) * 16] & (n - 1);
      const auto *state = v + (j / spacing) * words;
      if (j % spacing) {
        memcpy(checkpoint, state, block_bytes);
        for (unsigned step = 0; step < j % spacing; ++step) blockmix(checkpoint, y, r);
        state = checkpoint;
      }
      for (size_t k = 0; k < words; ++k) x[k] ^= state[k];
      blockmix(x, y, r);
      if (!(i & 255) && control.progress && !control.progress(control.context)) return WalletError::Aborted;
    }
    for (size_t j = 0; j < words; ++j) write32(b + lane * block_bytes + 4 * j, x[j]);
  }
  return crypto_pbkdf2_sha256(password, password_size, b, p * block_bytes, 1, out, out_size)
      ? WalletError::Ok : WalletError::CryptoFailure;
}
bool aes_block(const uint8_t key[32], const uint8_t in[16], uint8_t out[16], bool encrypt) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  int rc = encrypt ? mbedtls_aes_setkey_enc(&aes, key, 256) : mbedtls_aes_setkey_dec(&aes, key, 256);
  if (!rc) rc = mbedtls_aes_crypt_ecb(&aes, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, in, out);
  mbedtls_aes_free(&aes);
  return rc == 0;
}
WalletError address_hash(const BitcoinPrivateKey &key, uint8_t out[32]) {
  char address[36];
  const auto rc = bitcoin_key_address(key, address, sizeof(address));
  if (rc != WalletError::Ok) return rc;
  return crypto_double_sha256(reinterpret_cast<const uint8_t *>(address), strlen(address), out)
      ? WalletError::Ok : WalletError::CryptoFailure;
}
}

WalletError bitcoin_key_address(const BitcoinPrivateKey &key, char *out, size_t capacity) {
  if (!out || !capacity) return WalletError::InvalidArgument;
  out[0] = 0;
  if (!valid_network(key.network) || !valid_scalar(key.bytes)) return WalletError::InvalidKey;
  uint8_t pub[65];
  WalletError rc = key.compressed ? public_key_from_private(key.bytes, pub) : uncompressed_public_key_from_private(key.bytes, pub);
  if (rc != WalletError::Ok) return rc;
  uint8_t payload[25];
  payload[0] = key.network == BitcoinKeyNetwork::Mainnet ? 0 : 0x6f;
  if (!crypto_hash160(pub, key.compressed ? 33 : 65, payload + 1)) return WalletError::CryptoFailure;
  return checked_encode(payload, 21, out, capacity);
}
namespace {
bool multiply_scalars(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]) {
  mbedtls_mpi x, y, n, z;
  mbedtls_mpi_init(&x); mbedtls_mpi_init(&y); mbedtls_mpi_init(&n); mbedtls_mpi_init(&z);
  const bool ok = mbedtls_mpi_read_binary(&x, a, 32) == 0 && mbedtls_mpi_read_binary(&y, b, 32) == 0 &&
      mbedtls_mpi_read_string(&n, 16, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141") == 0 &&
      mbedtls_mpi_mul_mpi(&z, &x, &y) == 0 && mbedtls_mpi_mod_mpi(&z, &z, &n) == 0 &&
      mbedtls_mpi_write_binary(&z, out, 32) == 0;
  mbedtls_mpi_free(&x); mbedtls_mpi_free(&y); mbedtls_mpi_free(&n); mbedtls_mpi_free(&z);
  return ok;
}
}

WalletError private_key_decode(const char *text, size_t length, BitcoinKeyNetwork network,
                               bool hex_compressed, BitcoinPrivateKey *out) {
  if (!out) return WalletError::InvalidArgument;
  secure_zero(out, sizeof(*out));
  if (!text || !valid_network(network)) return WalletError::InvalidArgument;
  SensitiveValue<BitcoinPrivateKey> key;
  key.get().network = network;
  key.get().compressed = hex_compressed;
  if (length == 64) {
    for (size_t i = 0; i < 32; ++i) {
      const int hi = nibble(text[2*i]), lo = nibble(text[2*i+1]);
      if (hi < 0 || lo < 0) return WalletError::UnsupportedFormat;
      key.get().bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
  } else {
    if (length != 51 && length != 52) return WalletError::UnsupportedFormat;
    SensitiveValue<uint8_t[38]> payload;
    size_t size = sizeof(payload.get());
    const auto rc = checked_decode(text, length, payload.get(), &size);
    if (rc != WalletError::Ok) return rc;
    if (size != 33 && size != 34) return WalletError::UnsupportedFormat;
    if (payload.get()[0] != (network == BitcoinKeyNetwork::Mainnet ? 0x80 : 0xef)) return WalletError::WrongNetwork;
    if (size == 34 && payload.get()[33] != 1) return WalletError::UnsupportedFormat;
    key.get().compressed = size == 34;
    memcpy(key.get().bytes, payload.get() + 1, 32);
  }
  if (!valid_scalar(key.get().bytes)) return WalletError::InvalidKey;
  *out = key.get();
  return WalletError::Ok;
}
WalletError private_key_encode_wif(const BitcoinPrivateKey &key, char *out, size_t capacity) {
  if (!out) return WalletError::InvalidArgument;
  secure_zero(out, capacity);
  if (capacity < (key.compressed ? 53U : 52U)) return WalletError::BufferTooSmall;
  if (!valid_network(key.network) || !valid_scalar(key.bytes)) return WalletError::InvalidKey;
  SensitiveValue<uint8_t[38]> payload;
  payload.get()[0] = key.network == BitcoinKeyNetwork::Mainnet ? 0x80 : 0xef;
  memcpy(payload.get() + 1, key.bytes, 32);
  payload.get()[33] = 1;
  return checked_encode(payload.get(), key.compressed ? 34 : 33, out, capacity);
}
WalletError bip38_encrypt(const BitcoinPrivateKey &key, const uint8_t *passphrase, size_t length,
                         char *out, size_t capacity, KeyBackupControl control) {
  if (!out) return WalletError::InvalidArgument;
  secure_zero(out, capacity);
  if (capacity < 59) return WalletError::BufferTooSmall;
  if (!valid_network(key.network) || !valid_scalar(key.bytes)) return WalletError::InvalidKey;
  SensitiveValue<uint8_t[18 * kBip39MaxPassphraseBytes]> normalized;
  size_t size;
  auto rc = normalize_passphrase(passphrase, length, UnicodeForm::Nfc, normalized.get(), sizeof(normalized.get()), &size);
  if (rc != WalletError::Ok) return rc;
  SensitiveValue<uint8_t[64]> derived;
  uint8_t hash[32];
  rc = address_hash(key, hash);
  if (rc != WalletError::Ok) return rc;
  rc = scrypt(normalized.get(), size, hash, 4, 16384, 8, 8, derived.get(), 64, control);
  if (rc != WalletError::Ok) return rc;
  uint8_t payload[43] = {1, 0x42, static_cast<uint8_t>(key.compressed ? 0xe0 : 0xc0)};
  memcpy(payload + 3, hash, 4);
  SensitiveValue<uint8_t[32]> x;
  for (size_t i = 0; i < 32; ++i) x.get()[i] = key.bytes[i] ^ derived.get()[i];
  if (!aes_block(derived.get() + 32, x.get(), payload + 7, true) ||
      !aes_block(derived.get() + 32, x.get() + 16, payload + 23, true)) return WalletError::CryptoFailure;
  return checked_encode(payload, 39, out, capacity);
}
WalletError bip38_decrypt(const char *encrypted, size_t encrypted_size, const uint8_t *passphrase,
                         size_t length, BitcoinKeyNetwork network, BitcoinPrivateKey *out,
                         KeyBackupControl control) {
  if (!out) return WalletError::InvalidArgument;
  secure_zero(out, sizeof(*out));
  if (!encrypted || !valid_network(network)) return WalletError::InvalidArgument;
  if (encrypted_size != 58) return WalletError::UnsupportedFormat;
  uint8_t payload[43];
  size_t size = sizeof(payload);
  auto rc = checked_decode(encrypted, encrypted_size, payload, &size);
  if (rc != WalletError::Ok) return rc;
  if (size != 39 || payload[0] != 1 ||
      (payload[1] != 0x42 && payload[1] != 0x43)) return WalletError::UnsupportedFormat;
  const bool ec = payload[1] == 0x43;
  if (ec ? (payload[2] & ~0x24) != 0 : (payload[2] != 0xc0 && payload[2] != 0xe0))
    return WalletError::UnsupportedFormat;
  SensitiveValue<uint8_t[18 * kBip39MaxPassphraseBytes]> normalized;
  rc = normalize_passphrase(passphrase, length, UnicodeForm::Nfc, normalized.get(), sizeof(normalized.get()), &size);
  if (rc != WalletError::Ok) return rc;
  SensitiveValue<BitcoinPrivateKey> key;
  key.get().network = network;
  key.get().compressed = (payload[2] & 0x20) != 0;
  SensitiveValue<uint8_t[64]> derived;
  if (!ec) {
    rc = scrypt(normalized.get(), size, payload + 3, 4, 16384, 8, 8, derived.get(), 64, control);
    if (rc != WalletError::Ok) return rc;
    if (!aes_block(derived.get() + 32, payload + 7, key.get().bytes, false) ||
        !aes_block(derived.get() + 32, payload + 23, key.get().bytes + 16, false)) return WalletError::CryptoFailure;
    for (size_t i = 0; i < 32; ++i) key.get().bytes[i] ^= derived.get()[i];
  } else {
    const bool lot = (payload[2] & 4) != 0;
    SensitiveValue<uint8_t[40]> prefactor;
    SensitiveValue<uint8_t[32]> passfactor;
    rc = scrypt(normalized.get(), size, payload + 7, lot ? 4 : 8, 16384, 8, 8, prefactor.get(), 32, control);
    if (rc != WalletError::Ok) return rc;
    if (lot) {
      memcpy(prefactor.get() + 32, payload + 7, 8);
      if (!crypto_double_sha256(prefactor.get(), 40, passfactor.get())) return WalletError::CryptoFailure;
    } else memcpy(passfactor.get(), prefactor.get(), 32);
    uint8_t passpoint[33];
    if (!valid_scalar(passfactor.get())) return WalletError::IncorrectPassphrase;
    if (public_key_from_private(passfactor.get(), passpoint) != WalletError::Ok) return WalletError::CryptoFailure;
    rc = scrypt(passpoint, 33, payload + 3, 12, 1024, 1, 1, derived.get(), 64, control);
    if (rc != WalletError::Ok) return rc;
    SensitiveValue<uint8_t[24]> seed;
    SensitiveValue<uint8_t[16]> part;
    if (!aes_block(derived.get() + 32, payload + 23, part.get(), false)) return WalletError::CryptoFailure;
    for (size_t i = 0; i < 16; ++i) part.get()[i] ^= derived.get()[16 + i];
    memcpy(seed.get() + 16, part.get() + 8, 8);
    memcpy(part.get() + 8, part.get(), 8);
    memcpy(part.get(), payload + 15, 8);
    if (!aes_block(derived.get() + 32, part.get(), seed.get(), false)) return WalletError::CryptoFailure;
    for (size_t i = 0; i < 16; ++i) seed.get()[i] ^= derived.get()[i];
    SensitiveValue<uint8_t[32]> factor;
    if (!crypto_double_sha256(seed.get(), 24, factor.get()) ||
        !multiply_scalars(passfactor.get(), factor.get(), key.get().bytes)) return WalletError::CryptoFailure;
  }
  if (!valid_scalar(key.get().bytes)) return WalletError::IncorrectPassphrase;
  uint8_t hash[32];
  rc = address_hash(key.get(), hash);
  if (rc != WalletError::Ok) return rc;
  // BIP38 has no network field. A mismatched address hash may mean the wrong
  // password OR the wrong selected Bitcoin network; the UI must explain both.
  if (!crypto_constant_time_equal(hash, payload + 3, 4)) return WalletError::IncorrectPassphrase;
  *out = key.get();
  return WalletError::Ok;
}
}
