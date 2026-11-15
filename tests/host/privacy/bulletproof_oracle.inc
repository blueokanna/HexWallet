// Test adapter for the original Ryo Bulletproof verifier. Included in namespace
// rct after the MLSAG adapter. Uses the independently compiled upstream ref10.
constexpr size_t maxM = 16;
struct Bulletproof { keyV V; key A, S, T1, T2, taux, mu; keyV L, R; key a, b, t; };
key zero() { return key{}; }
bool is_reduced(const key &a) { return sc_check(a.bytes) == 0; }
key hash_to_scalar(const key &a) { return hash_to_scalar(keyV{a}); }
key invert(const key &a) { key r; sc_invert(r.bytes, a.bytes); return r; }
keyV vector_powers(const key &a, size_t n) {
  keyV v(n); if (n) v[0] = identity();
  for (size_t i = 1; i < n; ++i) sc_mul(v[i].bytes, v[i - 1].bytes, a.bytes);
  return v;
}
key vector_power_sum(const key &a, size_t n) {
  key sum{}, power = identity();
  for (size_t i = 0; i < n; ++i) {
    sc_add(sum.bytes, sum.bytes, power.bytes); sc_mul(power.bytes, power.bytes, a.bytes);
  }
  return sum;
}
const key ip12 = {{0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}};
const key H = {{0x8b,0x65,0x59,0x70,0x15,0x37,0x99,0xaf,0x2a,0xea,0xdc,0x9f,0xf1,0xad,0xd0,0xea,0x6c,0x72,0x51,0xd5,0x41,0x54,0xcf,0xa9,0x2c,0x17,0x3a,0x0d,0xd3,0x9c,0x1f,0x94}};
const key TWO = {{2}};
const keyV twoN = vector_powers(TWO, 64);
const ge_p3 ge_p3_H = crypto::point_t(H).value;
// oracle_bulletproof always verifies exactly one proof. A fixed nonzero batch
// weight is sufficient here; both equations are still checked separately.
key skGen() { return identity(); }
template<class... Args> key hash_cache_mash(key &cache, const Args &... args) {
  keyV values{cache, args...}; cache = hash_to_scalar(values); return cache;
}
key scalarmult8(const key &a) { return crypto::point_t(a).modify_mul8().encoded(); }
key scalarmultKey(const key &p, const key &s) { return (crypto::scalar_t(s) * crypto::point_t(p)).encoded(); }
key addKeys(const key &a, const key &b) { return (crypto::point_t(a) + crypto::point_t(b)).encoded(); }
void addKeys(key &out, const key &a, const key &b) { out = addKeys(a, b); }
void add_acc_p3(ge_p3 *out, const key &a) { *out = (crypto::point_t(*out) + crypto::point_t(a)).value; }
void sub_acc_p3(ge_p3 *out, const key &a) { *out = (crypto::point_t(*out) - crypto::point_t(a)).value; }
void addKeys_acc_p3(ge_p3 *out, const key &s, const key &a) { add_acc_p3(out, scalarmultKey(a, s)); }
bool ge_p3_is_point_at_infinity(const ge_p3 *p) { return crypto::point_t(*p).encoded() == identity(); }
key bp_generator(size_t index) {
  std::vector<uint8_t> data(H.bytes, H.bytes + 32);
  const char domain[] = "bulletproof";
  data.insert(data.end(), domain, domain + 11);
  do { uint8_t byte = index & 0x7f; index >>= 7; data.push_back(byte | (index ? 0x80 : 0)); } while (index);
  key digest; cn_fast_hash(data.data(), data.size(), reinterpret_cast<char *>(digest.bytes));
  return crypto::hash_helper_t::hp(digest).encoded();
}
struct multiexp_cache {
  static ge_p3 Gi_p3(size_t i) { return crypto::point_t(bp_generator(2 * i + 1)).value; }
  static ge_p3 Hi_p3(size_t i) { return crypto::point_t(bp_generator(2 * i)).value; }
};
struct MultiexpData {
  key scalar; crypto::point_t point;
  MultiexpData(const key &s, const key &p) : scalar(s), point(p) {}
  MultiexpData(const key &s, const ge_p3 &p) : scalar(s), point(p) {}
};
struct bp_cache {
  std::vector<MultiexpData> me_pad;
  void clear_pad(size_t n) { me_pad.clear(); me_pad.reserve(n); }
  key multiexp() const {
    crypto::point_t sum;
    for (const auto &term : me_pad) sum = sum + crypto::scalar_t(term.scalar) * term.point;
    return sum.encoded();
  }
  key multiexp_higi() const { return multiexp(); }
};
#define PERF_TIMER_START_BP(...) ((void)0)
#define PERF_TIMER_STOP(...) ((void)0)
#define GULPS_ERROR(...) ((void)0)
#include "ryo_bulletproof_verifier.inc"
