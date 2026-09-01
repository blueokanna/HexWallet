#include "WalletAltAddresses.h"

#include <stdio.h>
#include <string.h>

#include "base58.h"
#include "CryptoExtended.h"
#include "CryptoPrimitives.h"
#include "WalletAddresses.h"
#include "WalletEngine.h"

namespace hexwallet {
namespace {

static bool selftest_report(const char *name, bool ok) {
  if (!ok) ::printf("FAIL: %s\n", name);
  return ok;
}

constexpr size_t kAltMaxPayloadSize = 64;

// base58check with a double-SHA256 checksum (Bitcoin family).
bool base58check_sha256(const uint8_t *payload, size_t payload_size,
                        char *out, size_t *in_out_size) {
  if (payload == nullptr || out == nullptr || in_out_size == nullptr ||
      payload_size > kAltMaxPayloadSize) {
    return false;
  }
  uint8_t checksum[kSha256Size];
  if (!crypto_double_sha256(payload, payload_size, checksum)) return false;
  uint8_t encoded[kAltMaxPayloadSize + 4];
  memcpy(encoded, payload, payload_size);
  memcpy(encoded + payload_size, checksum, 4);
  const bool ok = b58enc(out, in_out_size, encoded, payload_size + 4);
  secure_zero(checksum, sizeof(checksum));
  secure_zero(encoded, sizeof(encoded));
  return ok;
}

// base58check with a blake2b-256 checksum (Ergo).
bool base58check_blake2b(const uint8_t *payload, size_t payload_size,
                         char *out, size_t *in_out_size) {
  if (payload == nullptr || out == nullptr || in_out_size == nullptr ||
      payload_size > kAltMaxPayloadSize) {
    return false;
  }
  uint8_t checksum[32];
  if (!crypto_blake2b(payload, payload_size, checksum, sizeof(checksum))) {
    return false;
  }
  uint8_t encoded[kAltMaxPayloadSize + 4];
  memcpy(encoded, payload, payload_size);
  memcpy(encoded + payload_size, checksum, 4);
  const bool ok = b58enc(out, in_out_size, encoded, payload_size + 4);
  secure_zero(checksum, sizeof(checksum));
  secure_zero(encoded, sizeof(encoded));
  return ok;
}

bool hash160_of(const uint8_t *data, size_t size, uint8_t out[kRipemd160Size]) {
  return crypto_hash160(data, size, out);
}

}  // namespace

WalletError address_zcash_transparent(uint16_t p2pkh_version,
                                      uint16_t p2sh_version,
                                      const uint8_t public_key[kCompressedPublicKeySize],
                                      char *out, size_t *in_out_size) {
  if (public_key == nullptr || p2pkh_version == 0 || p2sh_version == 0) {
    return WalletError::InvalidArgument;
  }
  uint8_t hash[kRipemd160Size];
  if (!hash160_of(public_key, kCompressedPublicKeySize, hash)) {
    return WalletError::CryptoFailure;
  }
  uint8_t payload[2 + kRipemd160Size];
  payload[0] = static_cast<uint8_t>(p2pkh_version >> 8);
  payload[1] = static_cast<uint8_t>(p2pkh_version & 0xff);
  memcpy(payload + 2, hash, kRipemd160Size);
  const bool ok = base58check_sha256(payload, sizeof(payload), out, in_out_size);
  secure_zero(payload, sizeof(payload));
  secure_zero(hash, sizeof(hash));
  return ok ? WalletError::Ok : WalletError::BufferTooSmall;
}

WalletError address_cashaddr(const char *prefix,
                             const uint8_t public_key[kCompressedPublicKeySize],
                             char *out, size_t out_size) {
  if (prefix == nullptr || public_key == nullptr) return WalletError::InvalidArgument;
  uint8_t hash[kRipemd160Size];
  if (!hash160_of(public_key, kCompressedPublicKeySize, hash)) {
    return WalletError::CryptoFailure;
  }
  const bool ok = cashaddr_encode(prefix, 0, hash, sizeof(hash), out, out_size);
  secure_zero(hash, sizeof(hash));
  return ok ? WalletError::Ok : WalletError::BufferTooSmall;
}

WalletError address_solana(const uint8_t public_key[32], char *out,
                           size_t *in_out_size) {
  if (public_key == nullptr || out == nullptr || in_out_size == nullptr) {
    return WalletError::InvalidArgument;
  }
  const bool ok = b58enc(out, in_out_size, public_key, 32);
  return ok ? WalletError::Ok : WalletError::BufferTooSmall;
}

WalletError address_algorand(const uint8_t public_key[32], char *out,
                             size_t out_size) {
  if (public_key == nullptr || out == nullptr) return WalletError::InvalidArgument;
  uint8_t checksum[32];
  uint8_t payload[32 + 4];
  if (!crypto_sha512_256(public_key, 32, checksum)) {
    return WalletError::CryptoFailure;
  }
  memcpy(payload, public_key, 32);
  memcpy(payload + 32, checksum + 28, 4);  // last 4 bytes
  const bool ok = base32_encode(payload, sizeof(payload), out, out_size, false, false);
  secure_zero(checksum, sizeof(checksum));
  secure_zero(payload, sizeof(payload));
  return ok ? WalletError::Ok : WalletError::BufferTooSmall;
}

WalletError address_tezos_tz1(const uint8_t public_key[32], char *out,
                              size_t *in_out_size) {
  if (public_key == nullptr || out == nullptr || in_out_size == nullptr) {
    return WalletError::InvalidArgument;
  }
  uint8_t hash[20];
  if (!crypto_blake2b(public_key, 32, hash, sizeof(hash))) {
    return WalletError::CryptoFailure;
  }
  uint8_t payload[3 + 20];
  payload[0] = 0x06;
  payload[1] = 0xa1;
  payload[2] = 0x9f;
  memcpy(payload + 3, hash, 20);
  const bool ok = base58check_sha256(payload, sizeof(payload), out, in_out_size);
  secure_zero(payload, sizeof(payload));
  secure_zero(hash, sizeof(hash));
  return ok ? WalletError::Ok : WalletError::BufferTooSmall;
}

WalletError address_cardano_base(const uint8_t payment_key[32],
                                 const uint8_t stake_key[32], char *out,
                                 size_t out_size) {
  if (payment_key == nullptr || stake_key == nullptr || out == nullptr) {
    return WalletError::InvalidArgument;
  }
  uint8_t payment_hash[28];
  uint8_t stake_hash[28];
  if (!crypto_blake2b(payment_key, 32, payment_hash, sizeof(payment_hash)) ||
      !crypto_blake2b(stake_key, 32, stake_hash, sizeof(stake_hash))) {
    secure_zero(payment_hash, sizeof(payment_hash));
    secure_zero(stake_hash, sizeof(stake_hash));
    return WalletError::CryptoFailure;
  }
  uint8_t payload[1 + 28 + 28];
  payload[0] = 0x01;  // mainnet base: payment key hash + stake key hash
  memcpy(payload + 1, payment_hash, 28);
  memcpy(payload + 1 + 28, stake_hash, 28);
  const bool ok = bech32_encode("addr", payload, sizeof(payload), out, out_size, false);
  secure_zero(payload, sizeof(payload));
  secure_zero(payment_hash, sizeof(payment_hash));
  secure_zero(stake_hash, sizeof(stake_hash));
  return ok ? WalletError::Ok : WalletError::BufferTooSmall;
}

WalletError address_cosmos_bech32(const char *hrp,
                                  const uint8_t public_key[kCompressedPublicKeySize],
                                  char *out, size_t out_size) {
  if (hrp == nullptr || public_key == nullptr || out == nullptr) {
    return WalletError::InvalidArgument;
  }
  uint8_t hash[kRipemd160Size];
  if (!hash160_of(public_key, kCompressedPublicKeySize, hash)) {
    return WalletError::CryptoFailure;
  }
  const bool ok = bech32_encode(hrp, hash, sizeof(hash), out, out_size, false);
  secure_zero(hash, sizeof(hash));
  return ok ? WalletError::Ok : WalletError::BufferTooSmall;
}

WalletError address_avalanche_xp(const char *hrp,
                                 const uint8_t public_key[kCompressedPublicKeySize],
                                 char *out, size_t out_size) {
  if (hrp == nullptr || public_key == nullptr || out == nullptr) {
    return WalletError::InvalidArgument;
  }
  uint8_t hash[kRipemd160Size];
  if (!hash160_of(public_key, kCompressedPublicKeySize, hash)) {
    return WalletError::CryptoFailure;
  }
  uint8_t payload[1 + kRipemd160Size];
  payload[0] = 0x00;  // shortID version byte
  memcpy(payload + 1, hash, kRipemd160Size);
  // The "X-" chain alias is a display prefix, NOT part of the bech32 HRP:
  // the checksum is computed over the HRP alone (e.g. "avax").
  if (out_size < 2 + 1) {
    secure_zero(payload, sizeof(payload));
    return WalletError::BufferTooSmall;
  }
  out[0] = 'X';
  out[1] = '-';
  const bool ok = bech32_encode(hrp, payload, sizeof(payload), out + 2, out_size - 2, false);
  secure_zero(payload, sizeof(payload));
  secure_zero(hash, sizeof(hash));
  return ok ? WalletError::Ok : WalletError::BufferTooSmall;
}

WalletError address_kaspa(const uint8_t public_key[kCompressedPublicKeySize],
                          char *out, size_t out_size) {
  if (public_key == nullptr || out == nullptr) return WalletError::InvalidArgument;
  // x-only: drop the SEC1 prefix byte.
  const bool ok = kaspa_bech32_encode("kaspa", 0, public_key + 1, 32, out, out_size);
  return ok ? WalletError::Ok : WalletError::BufferTooSmall;
}

WalletError address_qubic(const uint8_t public_key[32], char *out,
                          size_t out_size) {
  if (public_key == nullptr || out == nullptr) return WalletError::InvalidArgument;
  uint8_t digest[32];
  if (!crypto_sha3_256(public_key, 32, digest)) {
    return WalletError::CryptoFailure;
  }
  const bool ok = qubic_base26_encode(digest, sizeof(digest), out, out_size);
  secure_zero(digest, sizeof(digest));
  return ok ? WalletError::Ok : WalletError::BufferTooSmall;
}

WalletError address_filecoin(const uint8_t public_key[kCompressedPublicKeySize],
                             char *out, size_t out_size) {
  if (public_key == nullptr || out == nullptr) return WalletError::InvalidArgument;
  uint8_t hash[20];
  if (!crypto_blake2b(public_key, kCompressedPublicKeySize, hash, sizeof(hash))) {
    return WalletError::CryptoFailure;
  }
  uint8_t payload[1 + 20];
  payload[0] = 0x01;  // f1 protocol byte
  memcpy(payload + 1, hash, 20);
  const bool ok = base32_encode(payload, sizeof(payload), out, out_size, true, false);
  secure_zero(payload, sizeof(payload));
  secure_zero(hash, sizeof(hash));
  return ok ? WalletError::Ok : WalletError::BufferTooSmall;
}

WalletError address_ergo(const uint8_t public_key[kCompressedPublicKeySize],
                         char *out, size_t *in_out_size) {
  if (public_key == nullptr || out == nullptr || in_out_size == nullptr) {
    return WalletError::InvalidArgument;
  }
  // mainnet P2PK: prefix byte = network(0x00) + type(0x01); content is the
  // compressed public key itself; checksum = blake2b256(prefix||content)[:4].
  uint8_t payload[1 + kCompressedPublicKeySize];
  payload[0] = 0x01;
  memcpy(payload + 1, public_key, kCompressedPublicKeySize);
  const bool ok = base58check_blake2b(payload, sizeof(payload), out, in_out_size);
  secure_zero(payload, sizeof(payload));
  return ok ? WalletError::Ok : WalletError::BufferTooSmall;
}

bool run_alt_address_self_tests() {
  // secp256k1 private key = 1 -> compressed public key.
  static const uint8_t kPkOne[kCompressedPublicKeySize] = {
      0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
      0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
      0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
  };
  // ed25519 seed = 32 x 0x01 -> public key.
  static const uint8_t kEdSeed[32] = {
      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
  };
  static const uint8_t kEdPk[32] = {
      0x8a, 0x88, 0xe3, 0xdd, 0x74, 0x09, 0xf1, 0x95, 0xfd, 0x52, 0xdb,
      0x2d, 0x3c, 0xba, 0x5d, 0x72, 0xca, 0x67, 0x09, 0xbf, 0x1d, 0x94,
      0x12, 0x1b, 0xf3, 0x74, 0x88, 0x01, 0xb4, 0x0f, 0x6f, 0x5c,
  };
  char address[kAddressTextSize];
  size_t address_size = sizeof(address);
  bool passed = true;

  passed = selftest_report("solana", address_solana(kEdPk, address, &address_size) == WalletError::Ok &&
           strcmp(address, "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9") == 0) && passed;
  address_size = sizeof(address);
  passed = selftest_report("tezos", address_tezos_tz1(kEdPk, address, &address_size) == WalletError::Ok &&
           strcmp(address, "tz1c8PEDNfj6UxoQM2XCyfTHM5KbGGgoqDrH") == 0) && passed;
  passed = selftest_report("algorand ed01", address_algorand(kEdPk, address, sizeof(address)) == WalletError::Ok &&
           strcmp(address, "RKEOHXLUBHYZL7KS3MWTZOS5OLFGOCN7DWKBEG7TOSEADNAPN5OOTUNSLE") == 0) && passed;
  // Algorand known vector (public key from go-algorand address tests).
  static const uint8_t kAlgoPk[32] = {
      0x26, 0xf7, 0x8a, 0xce, 0x0d, 0xc1, 0xf4, 0x13, 0xa3, 0x7b, 0x70,
      0xb0, 0xbf, 0xa6, 0x10, 0x91, 0x19, 0x71, 0xf0, 0x8d, 0xff, 0x05,
      0x98, 0x6f, 0xe5, 0x17, 0x89, 0x92, 0x9d, 0x01, 0x13, 0x6c,
  };
  passed = selftest_report("algorand go-algo", address_algorand(kAlgoPk, address, sizeof(address)) == WalletError::Ok &&
           strcmp(address, "E33YVTQNYH2BHI33OCYL7JQQSEMXD4EN74CZQ37FC6EZFHIBCNWOWXIZ5M") == 0) && passed;

  address_size = sizeof(address);
  passed = selftest_report("zcash t1", address_zcash_transparent(0x1cb8, 0x1cbd, kPkOne, address, &address_size) == WalletError::Ok &&
           strcmp(address, "t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs") == 0) && passed;
  passed = selftest_report("cashaddr bch", address_cashaddr("bitcoincash", kPkOne, address, sizeof(address)) == WalletError::Ok &&
           strcmp(address, "bitcoincash:qw508d6qejxtdg4y5r3zarvary0c5xw7k9e8dplv0") == 0) && passed;
  passed = selftest_report("cashaddr xec", address_cashaddr("ecash", kPkOne, address, sizeof(address)) == WalletError::Ok &&
           strcmp(address, "ecash:qw508d6qejxtdg4y5r3zarvary0c5xw7kjp6rx7xg") == 0) && passed;
  passed = selftest_report("cosmos cro", address_cosmos_bech32("cro", kPkOne, address, sizeof(address)) == WalletError::Ok &&
           strcmp(address, "cro1w508d6qejxtdg4y5r3zarvary0c5xw7kzxlrnf") == 0) && passed;
  passed = selftest_report("cosmos sei", address_cosmos_bech32("sei", kPkOne, address, sizeof(address)) == WalletError::Ok &&
           strcmp(address, "sei1w508d6qejxtdg4y5r3zarvary0c5xw7kh3xvfe") == 0) && passed;
  passed = selftest_report("avax", address_avalanche_xp("avax", kPkOne, address, sizeof(address)) == WalletError::Ok &&
           strcmp(address, "X-avax1qp63uahgrxged4z5jswyt5dn5v3lzsem6cl7ra9f") == 0) && passed;
  passed = selftest_report("kaspa pk1", address_kaspa(kPkOne, address, sizeof(address)) == WalletError::Ok &&
           strcmp(address, "kaspa:qpumuen7l8wthtz45p3ftn58pvrs9xlumvkuu2xet8egzkcklqtes4ypce9sf") == 0) && passed;
  passed = selftest_report("qubic ed01", address_qubic(kEdPk, address, sizeof(address)) == WalletError::Ok &&
           strcmp(address, "3ho582fh18iq3rk2pj66j31p6kd432947reg87frgi13fe3aino2q4c") == 0) && passed;
  passed = selftest_report("filecoin", address_filecoin(kPkOne, address, sizeof(address)) == WalletError::Ok &&
           strcmp(address, "aep2ssiu2xjqkewe3yertg2adajt6sc6ma") == 0) && passed;
  address_size = sizeof(address);
  passed = selftest_report("ergo", address_ergo(kPkOne, address, &address_size) == WalletError::Ok &&
           strcmp(address, "9fSgJ7BmUxBQJ454prQDQ7fQMBkXPLaAmDnimgTtjym6FYPHjAV") == 0) && passed;
  passed = selftest_report("cardano", address_cardano_base(kEdPk, kEdPk, address, sizeof(address)) == WalletError::Ok &&
           strcmp(address,
                  "addr1qyxk54m7j3q6mrkevcunryrwf4p7e68c93cjk8gzxkhlkpsddftha9zp4k8dje3exxgxun2ran50str39vwsydd0lvrqyqym9s") == 0) && passed;

  secure_zero(address, sizeof(address));
  (void)kEdSeed;
  return passed;
}

}  // namespace hexwallet
