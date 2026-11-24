#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>
extern "C" {
#include "crypto-ops.h"
void cn_fast_hash(const void *, size_t, char *);
int keccak(const uint8_t *, int, uint8_t *, int);
}
#ifdef _WIN32
#define EXPORT extern "C" __declspec(dllexport)
#else
#define EXPORT extern "C" __attribute__((visibility("default")))
#endif

namespace crypto {
struct bytes32 {
  uint8_t bytes[32]{};
};
using hash = bytes32;
using public_key = bytes32;
using key_image = bytes32;
struct scalar_t : bytes32 {
  scalar_t() = default;
  explicit scalar_t(const bytes32 &b) { memcpy(bytes, b.bytes, 32); }
  bool operator==(const scalar_t &b) const {
    return !memcmp(bytes, b.bytes, 32);
  }
};
struct point_t {
  ge_p3 value{};
  point_t() { ge_p3_0(&value); }
  explicit point_t(const ge_p3 &v) : value(v) {}
  explicit point_t(const bytes32 &b) {
    if (ge_frombytes_vartime(&value, b.bytes))
      throw std::runtime_error("bad point");
  }
  point_t &modify_mul8() {
    ge_p3 result;
    ge_mul8_p3(&result, &value);
    value = result;
    return *this;
  }
  bytes32 encoded() const {
    bytes32 b;
    ge_p3_tobytes(b.bytes, &value);
    return b;
  }
  bool is_in_main_subgroup() const {
    static const uint8_t order[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
        0xa2, 0xde, 0xf9, 0xde, 0x14, 0,    0,    0,    0,    0,    0,
        0,    0,    0,    0,    0,    0,    0,    0,    0,    0x10};
    ge_p3 result;
    ge_scalarmult_p3(&result, order, &value);
    auto b = point_t(result).encoded();
    bytes32 identity;
    identity.bytes[0] = 1;
    return !memcmp(b.bytes, identity.bytes, 32);
  }
};
point_t operator*(const scalar_t &s, const point_t &p) {
  ge_p3 r;
  ge_scalarmult_p3(&r, s.bytes, &p.value);
  return point_t(r);
}
point_t operator+(const point_t &p, const point_t &q) {
  ge_cached c;
  ge_p1p1 r;
  ge_p3 p3;
  ge_p3_to_cached(&c, &q.value);
  ge_add(&r, &p.value, &c);
  ge_p1p1_to_p3(&p3, &r);
  return point_t(p3);
}
point_t operator-(const point_t &p, const point_t &q) {
  ge_cached c;
  ge_p1p1 r;
  ge_p3 p3;
  ge_p3_to_cached(&c, &q.value);
  ge_sub(&r, &p.value, &c);
  ge_p1p1_to_p3(&p3, &r);
  return point_t(p3);
}
struct hash_helper_t {
  static point_t hp(const public_key &pk) {
    ge_p3 p;
    ge_bytes_hash_to_ec_32(&p, pk.bytes);
    return point_t(p);
  }
  struct hs_t {
    std::vector<uint8_t> data;
    explicit hs_t(size_t n) { data.reserve(n * 32); }
    void add(const uint8_t *p) { data.insert(data.end(), p, p + 32); }
    void add_scalar(const scalar_t &s) { add(s.bytes); }
    // Match crypto-sugar.h's implicit scalar_t(const crypto::hash&) when
    // the unmodified CLSAG body passes its message hash to add_scalar.
    void add_scalar(const bytes32 &h) {
      scalar_t s(h);
      sc_reduce32(s.bytes);
      add_scalar(s);
    }
    void add_pub_key(const bytes32 &b) { add(b.bytes); }
    void add_key_image(const bytes32 &b) { add(b.bytes); }
    void add_hash(const bytes32 &b) { add(b.bytes); }
    void add_point(const point_t &p) { add(p.encoded().bytes); }
    void add_32_chars(const char *p) {
      add(reinterpret_cast<const uint8_t *>(p));
    }
    hash calc_hash_no_reduce() {
      hash h;
      cn_fast_hash(data.data(), data.size(), reinterpret_cast<char *>(h.bytes));
      data.clear();
      return h;
    }
    scalar_t calc_hash() {
      scalar_t s(calc_hash_no_reduce());
      sc_reduce32(s.bytes);
      return s;
    }
  };
};
struct CLSAG_GGX_input_ref_t {
  public_key stealth_address, amount_commitment, blinded_asset_id;
};
struct CLSAG_GGX_signature {
  scalar_t c;
  std::vector<scalar_t> r_g, r_x;
  public_key K1, K2;
};
#include "zano_domains.inc"
#define DBG_PRINT(...) ((void)0)
#define DBG_VAL_PRINT(...) ((void)0)
#define CRYPTO_CHECK_AND_THROW_MES(c, m)                                       \
  do {                                                                         \
    if (!(c))                                                                  \
      throw std::runtime_error(m);                                             \
  } while (0)
#include "zano_constants.inc"
#include "zano_verifier.inc"
} // namespace crypto

namespace rct {
using std::vector;
using key = crypto::bytes32;
using keyV = vector<key>;
using keyM = vector<keyV>;
struct mgSig {
  keyM ss;
  keyV II;
  key cc;
};
struct geDsmp {
  key k;
};
bool operator==(const key &a, const key &b) {
  return !memcmp(a.bytes, b.bytes, 32);
}
key copy(const key &a) { return a; }
void copy(key &a, const key &b) { a = b; }
key identity() {
  key a;
  a.bytes[0] = 1;
  return a;
}
void precomp(key &a, const key &b) { a = b; }
void hashToPoint(key &out, const key &p) {
  out = crypto::hash_helper_t::hp(p).encoded();
}
void addKeys2(key &out, const key &s, const key &c, const key &p) {
  out = (crypto::scalar_t(s) * crypto::c_point_G +
         crypto::scalar_t(c) * crypto::point_t(p))
            .encoded();
}
void addKeys3(key &out, const key &s, const key &p, const key &c,
              const key &q) {
  out = (crypto::scalar_t(s) * crypto::point_t(p) +
         crypto::scalar_t(c) * crypto::point_t(q))
            .encoded();
}
key hash_to_scalar(const keyV &v) {
  key k;
  cn_fast_hash(v.data(), v.size() * 32, reinterpret_cast<char *>(k.bytes));
  sc_reduce32(k.bytes);
  return k;
}
#define GULPS_CHECK_AND_ASSERT_MES(c, result, m)                               \
  do {                                                                         \
    if (!(c))                                                                  \
      return result;                                                           \
  } while (0)
#include "bulletproof_oracle.inc"
#include "ryo_verifier.inc"
} // namespace rct

static crypto::bytes32 read32(const uint8_t *p) {
  crypto::bytes32 b;
  memcpy(b.bytes, p, 32);
  return b;
}

EXPORT int oracle_payment_pad(const uint8_t derivation[32], uint8_t pad[40]) {
  uint8_t input[33], state[200];
  memcpy(input, derivation, 32);
  input[32] = 0x55;
  if (keccak(input, 33, state, sizeof(state)) != 0)
    return 0;
  memcpy(pad, state, 40);
  return 1;
}

EXPORT int oracle_ryo(const uint8_t *message, const uint8_t *ring, size_t n,
                      const uint8_t *pseudo, const uint8_t *image,
                      const uint8_t *challenge, const uint8_t *responses) {
  try {
    if (n < 2 || n > 241)
      return 0;
    rct::keyM keys(n, rct::keyV(2));
    rct::mgSig sig;
    sig.ss.resize(n, rct::keyV(2));
    sig.cc = read32(challenge);
    sig.II.push_back(read32(image));
    for (size_t i = 0; i < n; ++i) {
      keys[i][0] = read32(ring + 64 * i);
      keys[i][1] = (crypto::point_t(read32(ring + 64 * i + 32)) -
                    crypto::point_t(read32(pseudo)))
                       .encoded();
      sig.ss[i][0] = read32(responses + 64 * i);
      sig.ss[i][1] = read32(responses + 64 * i + 32);
    }
    return rct::MLSAG_Ver(read32(message), keys, sig, 1) ? 1 : 0;
  } catch (...) {
    return 0;
  }
}
EXPORT int oracle_zano(const uint8_t *message, const uint8_t *ring, size_t n,
                       const uint8_t *amount, const uint8_t *asset,
                       const uint8_t *image, const uint8_t *k1,
                       const uint8_t *k2, const uint8_t *c, const uint8_t *rg,
                       const uint8_t *rx) {
  try {
    if (!n || n > 256)
      return 0;
    std::vector<crypto::CLSAG_GGX_input_ref_t> keys(n);
    crypto::CLSAG_GGX_signature sig;
    sig.c = crypto::scalar_t(read32(c));
    sig.K1 = read32(k1);
    sig.K2 = read32(k2);
    for (size_t i = 0; i < n; ++i) {
      keys[i] = {read32(ring + i * 96), read32(ring + i * 96 + 32),
                 read32(ring + i * 96 + 64)};
      sig.r_g.emplace_back(read32(rg + 32 * i));
      sig.r_x.emplace_back(read32(rx + 32 * i));
    }
    return crypto::verify_CLSAG_GGX(read32(message), keys, read32(amount),
                                    read32(asset), read32(image), sig)
               ? 1
               : 0;
  } catch (...) {
    return 0;
  }
}
EXPORT void oracle_x(uint8_t *out) {
  memcpy(out, crypto::c_point_X.encoded().bytes, 32);
}
EXPORT void oracle_g(uint8_t *out) {
  memcpy(out, crypto::c_point_G.encoded().bytes, 32);
}
EXPORT void oracle_hash(const uint8_t *data, size_t n, uint8_t *out) {
  cn_fast_hash(data, n, reinterpret_cast<char *>(out));
}
EXPORT void oracle_hp(const uint8_t *p, uint8_t *out) {
  memcpy(out, crypto::hash_helper_t::hp(read32(p)).encoded().bytes, 32);
}
EXPORT int oracle_mul(const uint8_t *p, const uint8_t *s, uint8_t *out) {
  try {
    memcpy(out,
           (crypto::scalar_t(read32(s)) * crypto::point_t(read32(p)))
               .encoded()
               .bytes,
           32);
    return 1;
  } catch (...) {
    return 0;
  }
}
EXPORT int oracle_add(const uint8_t *p, const uint8_t *q, uint8_t *out) {
  try {
    memcpy(out,
           (crypto::point_t(read32(p)) + crypto::point_t(read32(q)))
               .encoded()
               .bytes,
           32);
    return 1;
  } catch (...) {
    return 0;
  }
}
EXPORT void oracle_bp_generator(size_t index, uint8_t *out) {
  memcpy(out, rct::bp_generator(index).bytes, 32);
}
EXPORT int oracle_bulletproof(const uint8_t *data, size_t size) {
  try {
    if (!size || data[0] < 1 || data[0] > 16)
      return 0;
    const size_t n = data[0], base = 1 + n * 32;
    if (size < base + 290)
      return 0;
    const uint8_t *p = data + base;
    const size_t rounds = p[192];
    if (rounds < 6 || rounds > 10 || size != base + 290 + rounds * 64 ||
        p[193 + rounds * 32] != rounds)
      return 0;
    rct::Bulletproof proof;
    for (size_t i = 0; i < n; ++i)
      proof.V.push_back(read32(data + 1 + i * 32));
    proof.A = read32(p);
    proof.S = read32(p + 32);
    proof.T1 = read32(p + 64);
    proof.T2 = read32(p + 96);
    proof.taux = read32(p + 128);
    proof.mu = read32(p + 160);
    for (size_t i = 0; i < rounds; ++i) {
      proof.L.push_back(read32(p + 193 + i * 32));
      proof.R.push_back(read32(p + 194 + (rounds + i) * 32));
    }
    proof.a = read32(p + 194 + rounds * 64);
    proof.b = read32(p + 226 + rounds * 64);
    proof.t = read32(p + 258 + rounds * 64);
    return rct::bulletproof_VERIFY(
               std::vector<const rct::Bulletproof *>{&proof})
               ? 1
               : 0;
  } catch (...) {
    return 0;
  }
}
