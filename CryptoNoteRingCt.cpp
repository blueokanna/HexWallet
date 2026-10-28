#include "CryptoNoteRingCt.h"

#include <stdio.h>
#include <string.h>

#include "CryptoExtended.h"
#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

namespace hexwallet {
namespace {

const uint8_t kBasePoint[kCryptoNoteKeySize] = {
  0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
};
const uint8_t kScalarEight[kCryptoNoteKeySize] = { 8 };
const uint8_t kScalarOne[kCryptoNoteKeySize] = { 1 };
// 8^-1 mod L. CLSAG serializes the prime-order auxiliary image divided by 8.
const uint8_t kScalarInvEight[kCryptoNoteKeySize] = {
  0x79,0x2f,0xdc,0xe2,0x29,0xe5,0x06,0x61,0xd0,0xda,0x1c,0x7d,0xb3,0x9d,0xd3,0x07,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x06
};

bool scalar_is_reduced(const uint8_t scalar[kCryptoNoteKeySize]) {
  uint8_t reduced[kCryptoNoteKeySize];
  memcpy(reduced, scalar, sizeof(reduced));
  ed25519_scalar_reduce_mod_l(reduced);
  const bool equal = memcmp(reduced, scalar, sizeof(reduced)) == 0;
  secure_zero(reduced, sizeof(reduced));
  return equal;
}

size_t write_varint(uint8_t *out, uint64_t value) {
  size_t size = 0;
  while (value >= 0x80) {
    out[size++] = static_cast<uint8_t>(value) | 0x80;
    value >>= 7;
  }
  out[size++] = static_cast<uint8_t>(value);
  return size;
}

bool derivation_to_scalar(const uint8_t derivation[kCryptoNoteKeySize],
                          uint64_t output_index,
                          uint8_t out_scalar[kCryptoNoteKeySize]) {
  uint8_t buffer[kCryptoNoteKeySize + 10];
  memcpy(buffer, derivation, kCryptoNoteKeySize);
  const size_t size = kCryptoNoteKeySize + write_varint(buffer + kCryptoNoteKeySize,
                                                        output_index);
  const bool ok = cryptonote_hash_to_scalar(buffer, size, out_scalar);
  secure_zero(buffer, sizeof(buffer));
  return ok;
}

int hex_nibble(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

bool hex_decode(const char *text, uint8_t *out, size_t out_size) {
  if (text == nullptr || out == nullptr || strlen(text) != out_size * 2) return false;
  for (size_t index = 0; index < out_size; ++index) {
    const int high = hex_nibble(text[index * 2]);
    const int low = hex_nibble(text[index * 2 + 1]);
    if (high < 0 || low < 0) return false;
    out[index] = static_cast<uint8_t>((high << 4) | low);
  }
  return true;
}

bool hex_decode_var(const char *text, uint8_t *out, size_t capacity,
                    size_t *out_size) {
  if (text == nullptr || out == nullptr || out_size == nullptr) return false;
  const size_t length = strlen(text);
  if ((length & 1U) != 0 || length / 2 > capacity) return false;
  for (size_t index = 0; index < length / 2; ++index) {
    const int high = hex_nibble(text[index * 2]);
    const int low = hex_nibble(text[index * 2 + 1]);
    if (high < 0 || low < 0) return false;
    out[index] = static_cast<uint8_t>((high << 4) | low);
  }
  *out_size = length / 2;
  return true;
}

struct ScalarVector {
  const char *input;
  const char *expected;
};

struct DerivationVector {
  const char *public_key;
  const char *secret_key;
  const char *expected;
};

struct OutputVector {
  const char *derivation;
  uint64_t output_index;
  const char *base;
  const char *expected;
};

struct KeyImageVector {
  const char *public_key;
  const char *secret_key;
  const char *expected;
};

struct ViewTagVector {
  const char *derivation;
  uint64_t output_index;
  const char *expected;
};

const ScalarVector kScalarVectors[] = {
  { "59d28aeade98016722948bf596af0b7deb5dd641f1aa2a906bd4e1",
    "7d0b25809fc4032a81dd5b0f721a2b21f7f68157c834374f580876f5d91f7409" },
  { "60d9a4b96951481ab458",
    "b0955682b297dbcae4a5c1b6f21addb211d6180632b538472045b5d592c38109" },
};

const DerivationVector kDerivationVectors[] = {
  { "fdfd97d2ea9f1c25df773ff2c973d885653a3ee643157eb0ae2b6dd98f0b6984",
    "eb2bd1cf0c5e074f9dbf38ebbc99c316f54e21803048c687a3bb359f7a713b02",
    "4e0bd2c41325a1b89a9f7413d4d05e0a5a4936f241dccc3c7d0c539ffe00ef67" },
  { "1ebf8c3c296bb91708b09d9a8e0639ccfd72556976419c7dc7e6dfd7599218b9",
    "e49f363fd5c8fc1f8645983647ca33d7ec9db2d255d94cd538a3cc83153c5f04",
    "72903ec8f9919dfcec6efb5535490527b573b3d77f9890386d373c02bf368934" },
};

const OutputVector kPublicKeyVectors[] = {
  { "ca780b065e48091d910de90bcab2411db3d1a845e6d95cfd556af4138504c737", 217407,
    "6d9dd2068b9d6d643b407e360dfc5eb7a1f628fe2de8112a9e5731e8b3680c39",
    "d48008aff5f27d8fcdc2a3bf814ed3505530f598075f3bf7e868fea696b109f6" },
  { "13bb0039172efee53059c7a973dc5f6f3c0a07611ebb0f5609cd833d5d25846c", 1,
    "5ca5429e836cd4172b7427ca8dc639f39c299f1b8e0d00f9d3f9a5bb2e49251a",
    "52e0a76a5785d12737dba717fd6c90e0e7d7a1a6c758543758abe578793c7a52" },
};

const OutputVector kSecretKeyVectors[] = {
  { "0fc47054f355ced4d67de73bfa12e4c78ff19089548fffa7d07a674741860f97", 66,
    "5619c62aa4ad787274b1071598b6ecacf4f9dacca2fd11b0c80741b744400500",
    "55297d64b0c0556d5583ce0e30c2024ccce90c93d16bdeb4e40fce7afff87803" },
  { "fea25a8d0184526c85c16c032c7678c7a1e3ace773b31566d159dc8a3cb81ae1", 755,
    "265685f284fe213678cad94e337196428237ac55edb5871c1f0209769ba9a803",
    "e83934c766427920055d77755b7205156e1bffc37f68135182f0974fe008470c" },
};

const KeyImageVector kKeyImageVectors[] = {
  { "e46b60ebfe610b8ba761032018471e5719bb77ea1cd945475c4a4abe7224bfd0",
    "981d477fb18897fa1f784c89721a9d600bf283f06b89cb018a077f41dcefef0f",
    "a637203ec41eab772532d30420eac80612fce8e44f1758bc7e2cb1bdda815887" },
  { "8661153f5f856b46f83e9e225777656cd95584ab16396fa03749ec64e957283b",
    "156d7f2e20899371404b87d612c3587ffe9fba294bafbbc99bb1695e3275230e",
    "03ec63d7f1b722f551840b2725c76620fa457c805cbbf2ee941a6bf4cfb6d06c" },
};

const ViewTagVector kViewTagVectors[] = {
  { "0fc47054f355ced4d67de73bfa12e4c78ff19089548fffa7d07a674741860f97", 0, "76" },
  { "0fc47054f355ced4d67de73bfa12e4c78ff19089548fffa7d07a674741860f97", 1, "d6" },
};

#include "src/generated/ClsagReferenceVectorTest.inc"

}  // namespace

bool cryptonote_hash_to_scalar(const uint8_t *data, size_t size,
                               uint8_t out_scalar[kCryptoNoteKeySize]) {
  if (out_scalar == nullptr || (data == nullptr && size != 0)) return false;
  static const uint8_t kEmpty = 0;
  const uint8_t *input = data == nullptr ? &kEmpty : data;
  uint8_t digest[kCryptoNoteKeySize];
  const bool hashed = crypto_keccak256(input, size, digest);
  if (hashed) {
    ed25519_scalar_reduce_mod_l(digest);
    memcpy(out_scalar, digest, sizeof(digest));
  }
  secure_zero(digest, sizeof(digest));
  return hashed;
}

bool cryptonote_generate_key_derivation(
    const uint8_t public_key[kCryptoNoteKeySize],
    const uint8_t secret_key[kCryptoNoteKeySize],
    uint8_t out_derivation[kCryptoNoteKeySize]) {
  if (public_key == nullptr || secret_key == nullptr || out_derivation == nullptr ||
      !scalar_is_reduced(secret_key)) {
    return false;
  }
  uint8_t point[kCryptoNoteKeySize];
  bool ok = ed25519_point_mul_compressed(public_key, secret_key, point) &&
            ed25519_point_mul_compressed(point, kScalarEight, out_derivation);
  secure_zero(point, sizeof(point));
  return ok;
}

bool cryptonote_derive_public_key(
    const uint8_t derivation[kCryptoNoteKeySize], uint64_t output_index,
    const uint8_t base_public[kCryptoNoteKeySize],
    uint8_t out_public[kCryptoNoteKeySize]) {
  if (derivation == nullptr || base_public == nullptr || out_public == nullptr) {
    return false;
  }
  uint8_t scalar[kCryptoNoteKeySize];
  uint8_t offset[kCryptoNoteKeySize];
  bool ok = derivation_to_scalar(derivation, output_index, scalar) &&
            ed25519_point_mul_compressed(kBasePoint, scalar, offset) &&
            ed25519_point_add_compressed(base_public, offset, out_public);
  secure_zero(scalar, sizeof(scalar));
  secure_zero(offset, sizeof(offset));
  return ok;
}

bool cryptonote_derive_secret_key(
    const uint8_t derivation[kCryptoNoteKeySize], uint64_t output_index,
    const uint8_t base_secret[kCryptoNoteKeySize],
    uint8_t out_secret[kCryptoNoteKeySize]) {
  if (derivation == nullptr || base_secret == nullptr || out_secret == nullptr ||
      !scalar_is_reduced(base_secret)) {
    return false;
  }
  uint8_t scalar[kCryptoNoteKeySize];
  const bool ok = derivation_to_scalar(derivation, output_index, scalar);
  if (ok) {
    ed25519_scalar_muladd(out_secret, scalar, kScalarOne, base_secret);
  }
  secure_zero(scalar, sizeof(scalar));
  return ok;
}

bool cryptonote_hash_to_point(const uint8_t public_key[kCryptoNoteKeySize],
                              uint8_t out_point[kCryptoNoteKeySize]) {
  if (public_key == nullptr || out_point == nullptr) return false;
  uint8_t digest[kCryptoNoteKeySize];
  const bool ok = crypto_keccak256(public_key, kCryptoNoteKeySize, digest) &&
                  ed25519_hash_to_point(digest, out_point);
  secure_zero(digest, sizeof(digest));
  return ok;
}

bool cryptonote_key_image_generator(
    const uint8_t public_key[kCryptoNoteKeySize],
    uint8_t out_generator[kCryptoNoteKeySize]) {
  if (public_key == nullptr || out_generator == nullptr) return false;
  uint8_t point[kCryptoNoteKeySize];
  const bool ok = cryptonote_hash_to_point(public_key, point) &&
                  ed25519_point_mul_compressed(point, kScalarEight,
                                               out_generator);
  secure_zero(point, sizeof(point));
  return ok;
}

bool cryptonote_generate_key_image(
    const uint8_t public_key[kCryptoNoteKeySize],
    const uint8_t secret_key[kCryptoNoteKeySize],
    uint8_t out_key_image[kCryptoNoteKeySize]) {
  if (public_key == nullptr || secret_key == nullptr || out_key_image == nullptr ||
      !scalar_is_reduced(secret_key)) {
    return false;
  }
  uint8_t generator[kCryptoNoteKeySize];
  const bool ok = cryptonote_key_image_generator(public_key, generator) &&
                  ed25519_point_mul_compressed(generator, secret_key,
                                               out_key_image);
  secure_zero(generator, sizeof(generator));
  return ok;
}

bool cryptonote_derivation_to_scalar(const uint8_t derivation[kCryptoNoteKeySize],
                                     uint64_t output_index,
                                     uint8_t out_scalar[kCryptoNoteKeySize]) {
  if (derivation == nullptr || out_scalar == nullptr) return false;
  return derivation_to_scalar(derivation, output_index, out_scalar);
}

bool cryptonote_scalar_to_point(const uint8_t scalar[kCryptoNoteKeySize],
                                uint8_t out_point[kCryptoNoteKeySize]) {
  if (scalar == nullptr || out_point == nullptr) return false;
  return ed25519_point_mul_compressed(kBasePoint, scalar, out_point);
}

bool cryptonote_derive_view_tag(const uint8_t derivation[kCryptoNoteKeySize],
                                uint64_t output_index, uint8_t *out_tag) {
  if (derivation == nullptr || out_tag == nullptr) return false;
  uint8_t buffer[8 + kCryptoNoteKeySize + 10];
  memcpy(buffer, "view_tag", 8);
  memcpy(buffer + 8, derivation, kCryptoNoteKeySize);
  const size_t size = 8 + kCryptoNoteKeySize +
                      write_varint(buffer + 8 + kCryptoNoteKeySize, output_index);
  uint8_t digest[kCryptoNoteKeySize];
  const bool ok = crypto_keccak256(buffer, size, digest);
  if (ok) *out_tag = digest[0];
  secure_zero(buffer, sizeof(buffer));
  secure_zero(digest, sizeof(digest));
  return ok;
}

namespace {

const uint8_t kIdentityPoint[kCryptoNoteKeySize] = { 1 };
const uint8_t kZeroScalar[kCryptoNoteKeySize] = { 0 };

bool is_identity(const uint8_t point[kCryptoNoteKeySize]) {
  return memcmp(point, kIdentityPoint, kCryptoNoteKeySize) == 0;
}

bool scalar_mul(uint8_t out[kCryptoNoteKeySize],
                const uint8_t left[kCryptoNoteKeySize],
                const uint8_t right[kCryptoNoteKeySize]) {
  ed25519_scalar_muladd(out, left, right, kZeroScalar);
  return true;
}

bool point_mul_base(const uint8_t scalar[kCryptoNoteKeySize],
                    uint8_t out[kCryptoNoteKeySize]) {
  return ed25519_point_mul_compressed(kBasePoint, scalar, out);
}

bool point_add3(const uint8_t first[kCryptoNoteKeySize],
                const uint8_t second[kCryptoNoteKeySize],
                const uint8_t third[kCryptoNoteKeySize],
                uint8_t out[kCryptoNoteKeySize]) {
  uint8_t sum[kCryptoNoteKeySize];
  const bool ok = ed25519_point_add_compressed(first, second, sum) &&
                  ed25519_point_add_compressed(sum, third, out);
  secure_zero(sum, sizeof(sum));
  return ok;
}

bool hash_key_vector(const uint8_t *keys, size_t count,
                     uint8_t out[kCryptoNoteKeySize]) {
  return cryptonote_hash_to_scalar(keys, count * kCryptoNoteKeySize, out);
}

bool clsag_aggregation_hash(const CryptoNoteRingMember *ring, size_t ring_size,
                            const uint8_t key_image[kCryptoNoteKeySize],
                            const uint8_t auxiliary[kCryptoNoteKeySize],
                            const uint8_t c_offset[kCryptoNoteKeySize],
                            const char *domain, uint8_t out[kCryptoNoteKeySize]) {
  uint8_t buffer[(2 * kCryptoNoteMaxRingSize + 4) * kCryptoNoteKeySize];
  memset(buffer, 0, sizeof(buffer));
  memcpy(buffer, domain, strlen(domain));
  uint8_t *cursor = buffer + kCryptoNoteKeySize;
  for (size_t index = 0; index < ring_size; ++index) {
    memcpy(cursor, ring[index].dest, kCryptoNoteKeySize);
    cursor += kCryptoNoteKeySize;
  }
  for (size_t index = 0; index < ring_size; ++index) {
    memcpy(cursor, ring[index].mask, kCryptoNoteKeySize);
    cursor += kCryptoNoteKeySize;
  }
  memcpy(cursor, key_image, kCryptoNoteKeySize);
  cursor += kCryptoNoteKeySize;
  memcpy(cursor, auxiliary, kCryptoNoteKeySize);
  cursor += kCryptoNoteKeySize;
  memcpy(cursor, c_offset, kCryptoNoteKeySize);
  const bool ok = hash_key_vector(buffer, 2 * ring_size + 4, out);
  secure_zero(buffer, sizeof(buffer));
  return ok;
}

bool clsag_round_hash(const CryptoNoteRingMember *ring, size_t ring_size,
                      const uint8_t c_offset[kCryptoNoteKeySize],
                      const uint8_t message[kCryptoNoteKeySize],
                      const uint8_t left[kCryptoNoteKeySize],
                      const uint8_t right[kCryptoNoteKeySize],
                      uint8_t out[kCryptoNoteKeySize]) {
  uint8_t buffer[(2 * kCryptoNoteMaxRingSize + 5) * kCryptoNoteKeySize];
  memset(buffer, 0, sizeof(buffer));
  memcpy(buffer, "CLSAG_round", 11);
  uint8_t *cursor = buffer + kCryptoNoteKeySize;
  for (size_t index = 0; index < ring_size; ++index) {
    memcpy(cursor, ring[index].dest, kCryptoNoteKeySize);
    cursor += kCryptoNoteKeySize;
  }
  for (size_t index = 0; index < ring_size; ++index) {
    memcpy(cursor, ring[index].mask, kCryptoNoteKeySize);
    cursor += kCryptoNoteKeySize;
  }
  memcpy(cursor, c_offset, kCryptoNoteKeySize);
  cursor += kCryptoNoteKeySize;
  memcpy(cursor, message, kCryptoNoteKeySize);
  cursor += kCryptoNoteKeySize;
  memcpy(cursor, left, kCryptoNoteKeySize);
  cursor += kCryptoNoteKeySize;
  memcpy(cursor, right, kCryptoNoteKeySize);
  const bool ok = hash_key_vector(buffer, 2 * ring_size + 5, out);
  secure_zero(buffer, sizeof(buffer));
  return ok;
}

}  // namespace

bool cryptonote_clsag_sign(const uint8_t message[kCryptoNoteKeySize],
                           const CryptoNoteRingMember *ring, size_t ring_size,
                           size_t index, const uint8_t p[kCryptoNoteKeySize],
                           const uint8_t z[kCryptoNoteKeySize],
                           const uint8_t nonce[kCryptoNoteKeySize],
                           const uint8_t *s_nonces,
                           const uint8_t c_offset[kCryptoNoteKeySize],
                           CryptoNoteClsag *out_signature) {
  if (message == nullptr || ring == nullptr || p == nullptr || z == nullptr ||
      nonce == nullptr || s_nonces == nullptr || c_offset == nullptr ||
      out_signature == nullptr || ring_size == 0 ||
      ring_size > kCryptoNoteMaxRingSize || index >= ring_size) {
    return false;
  }
  memset(out_signature, 0, sizeof(*out_signature));
  out_signature->ring_size = static_cast<uint8_t>(ring_size);

  uint8_t p_local[kCryptoNoteKeySize];
  uint8_t z_local[kCryptoNoteKeySize];
  uint8_t a[kCryptoNoteKeySize];
  memcpy(p_local, p, sizeof(p_local));
  memcpy(z_local, z, sizeof(z_local));
  memcpy(a, nonce, sizeof(a));
  ed25519_scalar_reduce_mod_l(a);
  bool ok = scalar_is_reduced(p_local) && scalar_is_reduced(z_local) &&
            memcmp(a, kZeroScalar, kCryptoNoteKeySize) != 0;
  if (!ok) {
    secure_zero(p_local, sizeof(p_local));
    secure_zero(z_local, sizeof(z_local));
    secure_zero(a, sizeof(a));
    return false;
  }

  uint8_t p_public[kCryptoNoteKeySize];
  uint8_t z_public[kCryptoNoteKeySize];
  uint8_t c_zero[kCryptoNoteKeySize];
  ok = point_mul_base(p_local, p_public) &&
       point_mul_base(z_local, z_public) &&
       ed25519_point_sub_compressed(ring[index].mask, c_offset, c_zero) &&
       crypto_constant_time_equal(p_public, ring[index].dest,
                                  kCryptoNoteKeySize) &&
       crypto_constant_time_equal(z_public, c_zero, kCryptoNoteKeySize);
  if (!ok) {
    secure_zero(p_local, sizeof(p_local));
    secure_zero(z_local, sizeof(z_local));
    secure_zero(a, sizeof(a));
    secure_zero(p_public, sizeof(p_public));
    secure_zero(z_public, sizeof(z_public));
    secure_zero(c_zero, sizeof(c_zero));
    return false;
  }

  uint8_t generators[kCryptoNoteMaxRingSize][kCryptoNoteKeySize];
  uint8_t zero_commitments[kCryptoNoteMaxRingSize][kCryptoNoteKeySize];
  for (size_t i = 0; i < ring_size; ++i) {
    ok = cryptonote_key_image_generator(ring[i].dest, generators[i]) &&
         ed25519_point_sub_compressed(ring[i].mask, c_offset,
                                      zero_commitments[i]);
    if (!ok) break;
  }
  if (!ok) {
    secure_zero(generators, sizeof(generators));
    secure_zero(zero_commitments, sizeof(zero_commitments));
    secure_zero(p_local, sizeof(p_local));
    secure_zero(z_local, sizeof(z_local));
    secure_zero(a, sizeof(a));
    secure_zero(p_public, sizeof(p_public));
    secure_zero(z_public, sizeof(z_public));
    secure_zero(c_zero, sizeof(c_zero));
    return false;
  }

  uint8_t key_image[kCryptoNoteKeySize];
  uint8_t auxiliary_full[kCryptoNoteKeySize];
  uint8_t auxiliary[kCryptoNoteKeySize];
  ok = ed25519_point_mul_compressed(generators[index], p_local, key_image) &&
       ed25519_point_mul_compressed(generators[index], z_local,
                                    auxiliary_full) &&
       ed25519_point_mul_compressed(auxiliary_full, kScalarInvEight, auxiliary);
  if (!ok) {
    secure_zero(generators, sizeof(generators));
    secure_zero(zero_commitments, sizeof(zero_commitments));
    secure_zero(key_image, sizeof(key_image));
    secure_zero(auxiliary_full, sizeof(auxiliary_full));
    secure_zero(auxiliary, sizeof(auxiliary));
    secure_zero(p_local, sizeof(p_local));
    secure_zero(z_local, sizeof(z_local));
    secure_zero(a, sizeof(a));
    secure_zero(p_public, sizeof(p_public));
    secure_zero(z_public, sizeof(z_public));
    secure_zero(c_zero, sizeof(c_zero));
    return false;
  }

  uint8_t alpha_g[kCryptoNoteKeySize];
  uint8_t alpha_h[kCryptoNoteKeySize];
  ok = point_mul_base(a, alpha_g) &&
       ed25519_point_mul_compressed(generators[index], a, alpha_h);
  if (!ok) {
    secure_zero(generators, sizeof(generators));
    secure_zero(zero_commitments, sizeof(zero_commitments));
    secure_zero(key_image, sizeof(key_image));
    secure_zero(auxiliary_full, sizeof(auxiliary_full));
    secure_zero(auxiliary, sizeof(auxiliary));
    secure_zero(alpha_g, sizeof(alpha_g));
    secure_zero(alpha_h, sizeof(alpha_h));
    secure_zero(p_local, sizeof(p_local));
    secure_zero(z_local, sizeof(z_local));
    secure_zero(a, sizeof(a));
    secure_zero(p_public, sizeof(p_public));
    secure_zero(z_public, sizeof(z_public));
    secure_zero(c_zero, sizeof(c_zero));
    return false;
  }

  uint8_t mu_p[kCryptoNoteKeySize];
  uint8_t mu_c[kCryptoNoteKeySize];
  ok = clsag_aggregation_hash(ring, ring_size, key_image, auxiliary, c_offset,
                              "CLSAG_agg_0", mu_p) &&
       clsag_aggregation_hash(ring, ring_size, key_image, auxiliary, c_offset,
                              "CLSAG_agg_1", mu_c);
  uint8_t c[kCryptoNoteKeySize];
  ok = ok && clsag_round_hash(ring, ring_size, c_offset, message, alpha_g,
                              alpha_h, c);
  if (!ok) {
    secure_zero(generators, sizeof(generators));
    secure_zero(zero_commitments, sizeof(zero_commitments));
    secure_zero(key_image, sizeof(key_image));
    secure_zero(auxiliary_full, sizeof(auxiliary_full));
    secure_zero(auxiliary, sizeof(auxiliary));
    secure_zero(alpha_g, sizeof(alpha_g));
    secure_zero(alpha_h, sizeof(alpha_h));
    secure_zero(mu_p, sizeof(mu_p));
    secure_zero(mu_c, sizeof(mu_c));
    secure_zero(c, sizeof(c));
    secure_zero(p_local, sizeof(p_local));
    secure_zero(z_local, sizeof(z_local));
    secure_zero(a, sizeof(a));
    secure_zero(p_public, sizeof(p_public));
    secure_zero(z_public, sizeof(z_public));
    secure_zero(c_zero, sizeof(c_zero));
    return false;
  }

  size_t cursor = (index + 1) % ring_size;
  if (cursor == 0) memcpy(out_signature->c1, c, kCryptoNoteKeySize);
  while (cursor != index) {
    uint8_t s[kCryptoNoteKeySize];
    memcpy(s, s_nonces + cursor * kCryptoNoteKeySize, kCryptoNoteKeySize);
    ed25519_scalar_reduce_mod_l(s);
    if (memcmp(s, kZeroScalar, kCryptoNoteKeySize) == 0) {
      ok = false;
      break;
    }
    memcpy(out_signature->s[cursor], s, kCryptoNoteKeySize);
    uint8_t c_p[kCryptoNoteKeySize];
    uint8_t c_c[kCryptoNoteKeySize];
    uint8_t s_g[kCryptoNoteKeySize];
    uint8_t c_p_p[kCryptoNoteKeySize];
    uint8_t c_c_c[kCryptoNoteKeySize];
    uint8_t s_h[kCryptoNoteKeySize];
    uint8_t c_p_i[kCryptoNoteKeySize];
    uint8_t c_c_d[kCryptoNoteKeySize];
    uint8_t left[kCryptoNoteKeySize];
    uint8_t right[kCryptoNoteKeySize];
    ok = scalar_mul(c_p, mu_p, c) && scalar_mul(c_c, mu_c, c) &&
         point_mul_base(s, s_g) &&
         ed25519_point_mul_compressed(ring[cursor].dest, c_p, c_p_p) &&
         ed25519_point_mul_compressed(zero_commitments[cursor], c_c, c_c_c) &&
         point_add3(s_g, c_p_p, c_c_c, left) &&
         ed25519_point_mul_compressed(generators[cursor], s, s_h) &&
         ed25519_point_mul_compressed(key_image, c_p, c_p_i) &&
         ed25519_point_mul_compressed(auxiliary_full, c_c, c_c_d) &&
         point_add3(s_h, c_p_i, c_c_d, right) &&
         clsag_round_hash(ring, ring_size, c_offset, message, left, right, c);
    secure_zero(s, sizeof(s));
    secure_zero(c_p, sizeof(c_p));
    secure_zero(c_c, sizeof(c_c));
    secure_zero(s_g, sizeof(s_g));
    secure_zero(c_p_p, sizeof(c_p_p));
    secure_zero(c_c_c, sizeof(c_c_c));
    secure_zero(s_h, sizeof(s_h));
    secure_zero(c_p_i, sizeof(c_p_i));
    secure_zero(c_c_d, sizeof(c_c_d));
    secure_zero(left, sizeof(left));
    secure_zero(right, sizeof(right));
    if (!ok) break;
    cursor = (cursor + 1) % ring_size;
    if (cursor == 0) memcpy(out_signature->c1, c, kCryptoNoteKeySize);
  }

  if (ok) {
    uint8_t product[kCryptoNoteKeySize];
    uint8_t sum[kCryptoNoteKeySize];
    ok = scalar_mul(product, mu_p, p_local);
    ed25519_scalar_muladd(sum, mu_c, z_local, product);
    if (ok) {
      ed25519_scalar_mulsub(out_signature->s[index], c, sum, a);
      memcpy(out_signature->I, key_image, kCryptoNoteKeySize);
      memcpy(out_signature->D, auxiliary, kCryptoNoteKeySize);
    }
    secure_zero(product, sizeof(product));
    secure_zero(sum, sizeof(sum));
  }

  secure_zero(generators, sizeof(generators));
  secure_zero(zero_commitments, sizeof(zero_commitments));
  secure_zero(key_image, sizeof(key_image));
  secure_zero(auxiliary_full, sizeof(auxiliary_full));
  secure_zero(auxiliary, sizeof(auxiliary));
  secure_zero(alpha_g, sizeof(alpha_g));
  secure_zero(alpha_h, sizeof(alpha_h));
  secure_zero(mu_p, sizeof(mu_p));
  secure_zero(mu_c, sizeof(mu_c));
  secure_zero(c, sizeof(c));
  secure_zero(p_local, sizeof(p_local));
  secure_zero(z_local, sizeof(z_local));
  secure_zero(a, sizeof(a));
  secure_zero(p_public, sizeof(p_public));
  secure_zero(z_public, sizeof(z_public));
  secure_zero(c_zero, sizeof(c_zero));
  return ok;
}

bool cryptonote_clsag_verify(const uint8_t message[kCryptoNoteKeySize],
                             const CryptoNoteRingMember *ring,
                             size_t ring_size,
                             const uint8_t c_offset[kCryptoNoteKeySize],
                             const CryptoNoteClsag &signature) {
  if (message == nullptr || ring == nullptr || c_offset == nullptr ||
      ring_size == 0 || ring_size > kCryptoNoteMaxRingSize ||
      signature.ring_size != ring_size || is_identity(signature.I) ||
      is_identity(signature.D)) {
    return false;
  }
  if (!scalar_is_reduced(signature.c1)) return false;
  for (size_t index = 0; index < ring_size; ++index) {
    if (!scalar_is_reduced(signature.s[index])) return false;
  }

  uint8_t auxiliary_full[kCryptoNoteKeySize];
  bool ok = ed25519_point_mul_compressed(signature.D, kScalarEight,
                                         auxiliary_full) &&
            !is_identity(auxiliary_full);
  uint8_t generators[kCryptoNoteMaxRingSize][kCryptoNoteKeySize];
  uint8_t zero_commitments[kCryptoNoteMaxRingSize][kCryptoNoteKeySize];
  for (size_t index = 0; ok && index < ring_size; ++index) {
    ok = cryptonote_key_image_generator(ring[index].dest, generators[index]) &&
         ed25519_point_sub_compressed(ring[index].mask, c_offset,
                                      zero_commitments[index]);
  }
  if (!ok) {
    secure_zero(auxiliary_full, sizeof(auxiliary_full));
    secure_zero(generators, sizeof(generators));
    secure_zero(zero_commitments, sizeof(zero_commitments));
    return false;
  }

  uint8_t mu_p[kCryptoNoteKeySize];
  uint8_t mu_c[kCryptoNoteKeySize];
  ok = clsag_aggregation_hash(ring, ring_size, signature.I, signature.D,
                              c_offset, "CLSAG_agg_0", mu_p) &&
       clsag_aggregation_hash(ring, ring_size, signature.I, signature.D,
                              c_offset, "CLSAG_agg_1", mu_c);
  uint8_t c[kCryptoNoteKeySize];
  memcpy(c, signature.c1, sizeof(c));
  for (size_t index = 0; ok && index < ring_size; ++index) {
    uint8_t c_p[kCryptoNoteKeySize];
    uint8_t c_c[kCryptoNoteKeySize];
    uint8_t s_g[kCryptoNoteKeySize];
    uint8_t c_p_p[kCryptoNoteKeySize];
    uint8_t c_c_c[kCryptoNoteKeySize];
    uint8_t s_h[kCryptoNoteKeySize];
    uint8_t c_p_i[kCryptoNoteKeySize];
    uint8_t c_c_d[kCryptoNoteKeySize];
    uint8_t left[kCryptoNoteKeySize];
    uint8_t right[kCryptoNoteKeySize];
    ok = scalar_mul(c_p, mu_p, c) && scalar_mul(c_c, mu_c, c) &&
         point_mul_base(signature.s[index], s_g) &&
         ed25519_point_mul_compressed(ring[index].dest, c_p, c_p_p) &&
         ed25519_point_mul_compressed(zero_commitments[index], c_c, c_c_c) &&
         point_add3(s_g, c_p_p, c_c_c, left) &&
         ed25519_point_mul_compressed(generators[index], signature.s[index],
                                      s_h) &&
         ed25519_point_mul_compressed(signature.I, c_p, c_p_i) &&
         ed25519_point_mul_compressed(auxiliary_full, c_c, c_c_d) &&
         point_add3(s_h, c_p_i, c_c_d, right) &&
         clsag_round_hash(ring, ring_size, c_offset, message, left, right, c);
    secure_zero(c_p, sizeof(c_p));
    secure_zero(c_c, sizeof(c_c));
    secure_zero(s_g, sizeof(s_g));
    secure_zero(c_p_p, sizeof(c_p_p));
    secure_zero(c_c_c, sizeof(c_c_c));
    secure_zero(s_h, sizeof(s_h));
    secure_zero(c_p_i, sizeof(c_p_i));
    secure_zero(c_c_d, sizeof(c_c_d));
    secure_zero(left, sizeof(left));
    secure_zero(right, sizeof(right));
  }
  const bool valid = ok && crypto_constant_time_equal(c, signature.c1,
                                                      kCryptoNoteKeySize);
  secure_zero(auxiliary_full, sizeof(auxiliary_full));
  secure_zero(generators, sizeof(generators));
  secure_zero(zero_commitments, sizeof(zero_commitments));
  secure_zero(mu_p, sizeof(mu_p));
  secure_zero(mu_c, sizeof(mu_c));
  secure_zero(c, sizeof(c));
  return valid;
}

bool run_cryptonote_ringct_self_tests() {
  bool passed = true;
  uint8_t input[128];
  size_t input_size = 0;
  uint8_t expected[kCryptoNoteKeySize];
  uint8_t actual[kCryptoNoteKeySize];

  bool section = true;
  for (const ScalarVector &vector : kScalarVectors) {
    section = hex_decode_var(vector.input, input, sizeof(input), &input_size) &&
              hex_decode(vector.expected, expected, sizeof(expected)) &&
              cryptonote_hash_to_scalar(input, input_size, actual) &&
              crypto_constant_time_equal(actual, expected, sizeof(expected)) &&
              section;
  }
  if (!section) printf("RINGCT_FAIL hash_to_scalar\n");
  passed = section && passed;

  section = true;
  for (const DerivationVector &vector : kDerivationVectors) {
    uint8_t public_key[kCryptoNoteKeySize];
    uint8_t secret_key[kCryptoNoteKeySize];
    section = hex_decode(vector.public_key, public_key, sizeof(public_key)) &&
              hex_decode(vector.secret_key, secret_key, sizeof(secret_key)) &&
              hex_decode(vector.expected, expected, sizeof(expected)) &&
              cryptonote_generate_key_derivation(public_key, secret_key, actual) &&
              crypto_constant_time_equal(actual, expected, sizeof(expected)) &&
              section;
    secure_zero(public_key, sizeof(public_key));
    secure_zero(secret_key, sizeof(secret_key));
  }
  if (!section) printf("RINGCT_FAIL generate_key_derivation\n");
  passed = section && passed;

  section = true;
  for (const OutputVector &vector : kPublicKeyVectors) {
    uint8_t derivation[kCryptoNoteKeySize];
    uint8_t base[kCryptoNoteKeySize];
    section = hex_decode(vector.derivation, derivation, sizeof(derivation)) &&
              hex_decode(vector.base, base, sizeof(base)) &&
              hex_decode(vector.expected, expected, sizeof(expected)) &&
              cryptonote_derive_public_key(derivation, vector.output_index, base,
                                           actual) &&
              crypto_constant_time_equal(actual, expected, sizeof(expected)) &&
              section;
    secure_zero(derivation, sizeof(derivation));
    secure_zero(base, sizeof(base));
  }
  if (!section) printf("RINGCT_FAIL derive_public_key\n");
  passed = section && passed;

  section = true;
  for (const OutputVector &vector : kSecretKeyVectors) {
    uint8_t derivation[kCryptoNoteKeySize];
    uint8_t base[kCryptoNoteKeySize];
    section = hex_decode(vector.derivation, derivation, sizeof(derivation)) &&
              hex_decode(vector.base, base, sizeof(base)) &&
              hex_decode(vector.expected, expected, sizeof(expected)) &&
              cryptonote_derive_secret_key(derivation, vector.output_index, base,
                                           actual) &&
              crypto_constant_time_equal(actual, expected, sizeof(expected)) &&
              section;
    secure_zero(derivation, sizeof(derivation));
    secure_zero(base, sizeof(base));
  }
  if (!section) printf("RINGCT_FAIL derive_secret_key\n");
  passed = section && passed;

  section = true;
  for (const KeyImageVector &vector : kKeyImageVectors) {
    uint8_t public_key[kCryptoNoteKeySize];
    uint8_t secret_key[kCryptoNoteKeySize];
    section = hex_decode(vector.public_key, public_key, sizeof(public_key)) &&
              hex_decode(vector.secret_key, secret_key, sizeof(secret_key)) &&
              hex_decode(vector.expected, expected, sizeof(expected)) &&
              cryptonote_generate_key_image(public_key, secret_key, actual) &&
              crypto_constant_time_equal(actual, expected, sizeof(expected)) &&
              section;
    secure_zero(public_key, sizeof(public_key));
    secure_zero(secret_key, sizeof(secret_key));
  }
  if (!section) printf("RINGCT_FAIL generate_key_image\n");
  passed = section && passed;

  section = true;
  for (const ViewTagVector &vector : kViewTagVectors) {
    uint8_t derivation[kCryptoNoteKeySize];
    uint8_t tag = 0;
    section = hex_decode(vector.derivation, derivation, sizeof(derivation)) &&
              hex_decode(vector.expected, expected, 1) &&
              cryptonote_derive_view_tag(derivation, vector.output_index, &tag) &&
              tag == expected[0] && section;
    secure_zero(derivation, sizeof(derivation));
  }
  if (!section) printf("RINGCT_FAIL derive_view_tag\n");
  passed = section && passed;

  section = true;
  static const uint8_t kScalarL[kCryptoNoteKeySize] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
  };
  uint8_t invalid_point[kCryptoNoteKeySize];
  memset(invalid_point, 0xff, sizeof(invalid_point));
  section = !cryptonote_hash_to_scalar(nullptr, 1, actual) &&
            !cryptonote_generate_key_derivation(kBasePoint, kScalarL, actual) &&
            !cryptonote_derive_public_key(kBasePoint, 0, invalid_point, actual) &&
            !cryptonote_derive_secret_key(kBasePoint, 0, kScalarL, actual) &&
            !cryptonote_generate_key_image(kBasePoint, kScalarL, actual) &&
            !cryptonote_derive_view_tag(nullptr, 0, actual) &&
            section;
  if (!section) printf("RINGCT_FAIL failure_paths\n");
  passed = section && passed;

  secure_zero(input, sizeof(input));
  secure_zero(expected, sizeof(expected));
  secure_zero(actual, sizeof(actual));
  return passed;
}

bool run_cryptonote_clsag_self_test() {
  // Verify an independently generated signature before the round-trip tests.
  // A two-member ring checks arithmetic only, not current network policy.
  {
    CryptoNoteRingMember reference_ring[2] = {};
    CryptoNoteClsag reference = {}, actual = {};
    uint8_t message[32], offset[32], secret[32];
    uint8_t z[32] = {3}, nonce[32] = {5}, responses[64] = {};
    responses[32] = 9;
    bool ok = hex_decode(kClsagReference[0], message, 32) &&
              hex_decode(kClsagReference[1], offset, 32) &&
              hex_decode(kClsagReference[2], reference.D, 32) &&
              hex_decode(kClsagReference[3], reference.c1, 32) &&
              hex_decode(kClsagReference[4], reference.s[0], 32) &&
              hex_decode(kClsagReference[5], reference.s[1], 32) &&
              hex_decode(kKeyImageVectors[0].expected, reference.I, 32) &&
              hex_decode(kKeyImageVectors[0].secret_key, secret, 32);
    reference.ring_size = 2;
    for (size_t i = 0; i < 2; ++i) {
      ok = hex_decode(kKeyImageVectors[i].public_key, reference_ring[i].dest, 32) &&
           hex_decode(kClsagReference[6 + i], reference_ring[i].mask, 32) && ok;
    }
    ok = ok && cryptonote_clsag_verify(message, reference_ring, 2, offset, reference) &&
         cryptonote_clsag_sign(message, reference_ring, 2, 0, secret, z, nonce,
                               responses, offset, &actual) &&
         crypto_constant_time_equal(actual.D, reference.D, 32) &&
         crypto_constant_time_equal(actual.I, reference.I, 32) &&
         crypto_constant_time_equal(actual.c1, reference.c1, 32) &&
         crypto_constant_time_equal(actual.s[0], reference.s[0], 64);
    secure_zero(secret, sizeof(secret)); secure_zero(z, sizeof(z));
    secure_zero(nonce, sizeof(nonce)); secure_zero(responses, sizeof(responses));
    secure_zero(&actual, sizeof(actual));
    if (!ok) { printf("CLSAG_FAIL independent-reference\n"); return false; }
  }
  {
    uint8_t two[32] = { 2 }, three[32] = { 3 }, ten[32] = { 10 };
    uint8_t expected_four[32] = { 4 };
    uint8_t actual[32];
    ed25519_scalar_mulsub(actual, two, three, ten);
    if (memcmp(actual, expected_four, sizeof(actual)) != 0) {
      printf("CLSAG_FAIL mulsub\n");
    }
    uint8_t five[32] = { 5 }, three_c[32] = { 3 };
    static const uint8_t expected_l_minus_22[32] = {
      0xd7, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
      0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    };
    ed25519_scalar_mulsub(actual, five, five, three_c);
    if (memcmp(actual, expected_l_minus_22, sizeof(actual)) != 0) {
      printf("CLSAG_FAIL mulsub2\n");
    }
    secure_zero(two, sizeof(two));
    secure_zero(three, sizeof(three));
    secure_zero(ten, sizeof(ten));
    secure_zero(actual, sizeof(actual));
  }
  CryptoNoteRingMember ring[3] = {};
  uint8_t signer_p[kCryptoNoteKeySize];
  uint8_t signer_z[kCryptoNoteKeySize];
  uint8_t nonce[kCryptoNoteKeySize];
  uint8_t offset_scalar[kCryptoNoteKeySize];
  uint8_t message[kCryptoNoteKeySize];
  uint8_t s_nonces[3 * kCryptoNoteKeySize];
  uint8_t offset_point[kCryptoNoteKeySize];
  bool passed =
      cryptonote_hash_to_scalar(reinterpret_cast<const uint8_t *>("clsag p"), 7,
                                signer_p) &&
      cryptonote_hash_to_scalar(reinterpret_cast<const uint8_t *>("clsag z"), 7,
                                signer_z) &&
      cryptonote_hash_to_scalar(reinterpret_cast<const uint8_t *>("clsag a"), 7,
                                nonce) &&
      cryptonote_hash_to_scalar(reinterpret_cast<const uint8_t *>("clsag offset"),
                                12, offset_scalar) &&
      cryptonote_hash_to_scalar(reinterpret_cast<const uint8_t *>("clsag message"),
                                13, message) &&
      point_mul_base(offset_scalar, offset_point);
  for (size_t index = 0; passed && index < 3; ++index) {
    char label[16] = { 0 };
    label[0] = 'p';
    label[1] = static_cast<char>('0' + index);
    uint8_t decoy_p[kCryptoNoteKeySize];
    passed = cryptonote_hash_to_scalar(reinterpret_cast<const uint8_t *>(label),
                                       2, decoy_p);
    label[0] = 'z';
    uint8_t decoy_z[kCryptoNoteKeySize];
    passed = passed &&
             cryptonote_hash_to_scalar(reinterpret_cast<const uint8_t *>(label),
                                       2, decoy_z);
    label[0] = 's';
    passed = passed &&
             cryptonote_hash_to_scalar(reinterpret_cast<const uint8_t *>(label),
                                       2, s_nonces + index * kCryptoNoteKeySize);
    uint8_t zero_commitment[kCryptoNoteKeySize];
    passed = passed && point_mul_base(decoy_p, ring[index].dest) &&
             point_mul_base(decoy_z, zero_commitment) &&
             ed25519_point_add_compressed(zero_commitment, offset_point,
                                          ring[index].mask);
    if (index == 1) {
      memcpy(signer_p, decoy_p, sizeof(signer_p));
      memcpy(signer_z, decoy_z, sizeof(signer_z));
    }
    secure_zero(decoy_p, sizeof(decoy_p));
    secure_zero(decoy_z, sizeof(decoy_z));
    secure_zero(zero_commitment, sizeof(zero_commitment));
  }

  if (passed) {
    uint8_t q_scalar[kCryptoNoteKeySize];
    uint8_t q[kCryptoNoteKeySize];
    uint8_t diff[kCryptoNoteKeySize];
    uint8_t back[kCryptoNoteKeySize];
    passed = cryptonote_hash_to_scalar(
                 reinterpret_cast<const uint8_t *>("clsag q"), 7, q_scalar) &&
             point_mul_base(q_scalar, q) &&
             ed25519_point_sub_compressed(q, ring[0].dest, diff) &&
             ed25519_point_add_compressed(diff, ring[0].dest, back) &&
             crypto_constant_time_equal(q, back, kCryptoNoteKeySize);
    if (!passed) printf("CLSAG_FAIL point-sub\n");
    secure_zero(q_scalar, sizeof(q_scalar));
    secure_zero(q, sizeof(q));
    secure_zero(diff, sizeof(diff));
    secure_zero(back, sizeof(back));
  }

  CryptoNoteClsag signature = {};
  if (passed) {
    const bool signed_ok = cryptonote_clsag_sign(
        message, ring, 3, 1, signer_p, signer_z, nonce, s_nonces, offset_point,
        &signature);
    if (!signed_ok) {
      printf("CLSAG_FAIL sign\n");
      passed = false;
    } else if (!cryptonote_clsag_verify(message, ring, 3, offset_point,
                                        signature)) {
      printf("CLSAG_FAIL verify\n");
      passed = false;
    }
  } else {
    printf("CLSAG_FAIL setup\n");
  }

  if (passed) {
    uint8_t full[32], canonical[32];
    // An uncofactored hash point times z may carry torsion. Merely verifying
    // 8*D would miss that: upstream serializes inv8*(z*hash_to_ec(P)).
    passed = ed25519_point_mul_compressed(signature.D, kScalarEight, full) &&
             ed25519_point_mul_compressed(full, kScalarInvEight, canonical) &&
             crypto_constant_time_equal(canonical, signature.D, 32) && passed;
    secure_zero(full, sizeof(full)); secure_zero(canonical, sizeof(canonical));
  }

  if (passed) {
    CryptoNoteClsag tampered = signature;
    tampered.s[0][0] ^= 1;
    if (cryptonote_clsag_verify(message, ring, 3, offset_point, tampered)) {
      printf("CLSAG_FAIL s-tamper\n");
      passed = false;
    }
  }
  if (passed) {
    uint8_t full[32], canonical[32];
    // An uncofactored hash point times z may carry torsion. Merely verifying
    // 8*D would miss that: upstream serializes inv8*(z*hash_to_ec(P)).
    passed = ed25519_point_mul_compressed(signature.D, kScalarEight, full) &&
             ed25519_point_mul_compressed(full, kScalarInvEight, canonical) &&
             crypto_constant_time_equal(canonical, signature.D, 32) && passed;
    secure_zero(full, sizeof(full)); secure_zero(canonical, sizeof(canonical));
  }

  if (passed) {
    CryptoNoteClsag tampered = signature;
    tampered.I[0] ^= 1;
    if (cryptonote_clsag_verify(message, ring, 3, offset_point, tampered)) {
      printf("CLSAG_FAIL I-tamper\n");
      passed = false;
    }
  }
  if (passed) {
    uint8_t wrong_message[kCryptoNoteKeySize];
    memcpy(wrong_message, message, sizeof(wrong_message));
    wrong_message[0] ^= 1;
    if (cryptonote_clsag_verify(wrong_message, ring, 3, offset_point,
                                signature)) {
      printf("CLSAG_FAIL message-tamper\n");
      passed = false;
    }
    secure_zero(wrong_message, sizeof(wrong_message));
  }

  secure_zero(ring, sizeof(ring));
  secure_zero(signature.s, sizeof(signature.s));
  secure_zero(signature.c1, sizeof(signature.c1));
  secure_zero(signature.I, sizeof(signature.I));
  secure_zero(signature.D, sizeof(signature.D));
  secure_zero(signer_p, sizeof(signer_p));
  secure_zero(signer_z, sizeof(signer_z));
  secure_zero(nonce, sizeof(nonce));
  secure_zero(offset_scalar, sizeof(offset_scalar));
  secure_zero(message, sizeof(message));
  secure_zero(s_nonces, sizeof(s_nonces));
  secure_zero(offset_point, sizeof(offset_point));
  return passed;
}

}  // namespace hexwallet
