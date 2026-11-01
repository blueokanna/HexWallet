#include "MlDsa87.h"

#include <stdlib.h>
#include <string.h>


#include "CryptoPrimitives.h"
#include "WalletSecurity.h"

// FIPS 204 ML-DSA-87, following the standard's Algorithms 6-8, 14-21, 28-29
// and 34-42.  This is an independent implementation: polynomial arithmetic is
// plain int32/int64 modular arithmetic, and the only shared primitives are
// SHAKE-128, SHAKE-256 and the zeroising wipe.
//
// One call needs about 140 KB of scratch space.  The workspace is allocated on
// the heap and wiped on every exit path; large polynomial arrays never live on
// the MCU stack.

namespace hexwallet
{
  namespace
  {

    constexpr int32_t kQ = 8380417;
    constexpr int32_t kD = 13;
    constexpr int32_t kK = 8;
    constexpr int32_t kL = 7;
    constexpr int32_t kEta = 2;
    constexpr int32_t kTau = 60;
    constexpr int32_t kBeta = 120;
    constexpr int32_t kGamma1 = 1 << 19;
    constexpr int32_t kGamma2 = (kQ - 1) / 32;
    constexpr int32_t kOmega = 75;
    constexpr size_t kN = 256;
    constexpr size_t kCTildeBytes = 64;
    constexpr size_t kHintBytes = kOmega + kK;
    constexpr size_t kT1PackedBytes = 320;
    constexpr size_t kT0PackedBytes = 416;
    constexpr size_t kEtaPackedBytes = 96;
    constexpr size_t kZPackedBytes = 640;
    constexpr size_t kW1PackedBytes = 128;
    constexpr uint32_t kMaxAttempts = 814;


    struct Poly
    {
      int32_t c[kN];
    };

    struct Workspace
    {
      Poly a[kK][kL];
      Poly s1[kL];
      Poly s2[kK];
      Poly t0[kK];
      Poly y[kL];
      Poly t1[kK];
      Poly w[kK];
      Poly cs2[kK];
      Poly ct0[kK];
      Poly h[kK];
      Poly z[kL];
      Poly accumulator;
      Poly product;
      Poly scratch;
      uint8_t stream[1680];
      uint8_t pk[kMlDsa87PublicKeySize];
      uint8_t sk[kMlDsa87SecretKeySize];
    };

    int32_t mod_q(int64_t value)
    {
      value %= kQ;
      if (value < 0)
        value += kQ;
      return static_cast<int32_t>(value);
    }

    int32_t centered(int32_t value)
    {
      return value > kQ / 2 ? value - kQ : value;
    }

    uint8_t bit_reverse8(uint8_t value)
    {
      value = static_cast<uint8_t>(((value & 0xF0) >> 4) | ((value & 0x0F) << 4));
      value = static_cast<uint8_t>(((value & 0xCC) >> 2) | ((value & 0x33) << 2));
      value = static_cast<uint8_t>(((value & 0xAA) >> 1) | ((value & 0x55) << 1));
      return value;
    }

    int32_t mod_pow(int32_t base, uint32_t exponent)
    {
      int64_t result = 1;
      int64_t factor = base;
      while (exponent != 0)
      {
        if ((exponent & 1) != 0)
          result = (result * factor) % kQ;
        factor = (factor * factor) % kQ;
        exponent >>= 1;
      }
      return static_cast<int32_t>(result);
    }

    // zetas[m] = 1753^BitRev8(m) mod q.
    const int32_t *zeta_table()
    {
      static int32_t table[kN];
      static bool ready = false;
      if (!ready)
      {
        for (size_t index = 0; index < kN; ++index)
        {
          table[index] = mod_pow(1753, bit_reverse8(static_cast<uint8_t>(index)));
        }
        ready = true;
      }
      return table;
    }

    void ntt(Poly &poly)
    {
      const int32_t *zetas = zeta_table();
      size_t m = 0;
      for (size_t len = 128; len >= 1; len >>= 1)
      {
        for (size_t start = 0; start < kN; start += 2 * len)
        {
          const int32_t z = zetas[++m];
          for (size_t j = start; j < start + len; ++j)
          {
            const int32_t t = mod_q(static_cast<int64_t>(z) * poly.c[j + len]);
            const int32_t u = poly.c[j];
            int32_t sum = u + t;
            if (sum >= kQ)
              sum -= kQ;
            int32_t difference = u - t;
            if (difference < 0)
              difference += kQ;
            poly.c[j] = sum;
            poly.c[j + len] = difference;
          }
        }
      }
    }

    void inverse_ntt(Poly &poly)
    {
      const int32_t *zetas = zeta_table();
      size_t m = kN;
      for (size_t len = 1; len < kN; len <<= 1)
      {
        for (size_t start = 0; start < kN; start += 2 * len)
        {
          const int32_t z = mod_q(-static_cast<int64_t>(zetas[--m]));
          for (size_t j = start; j < start + len; ++j)
          {
            const int32_t t = poly.c[j];
            int32_t sum = t + poly.c[j + len];
            if (sum >= kQ)
              sum -= kQ;
            const int32_t difference =
                mod_q(static_cast<int64_t>(z) * (t - poly.c[j + len]));
            poly.c[j] = sum;
            poly.c[j + len] = difference;
          }
        }
      }
      for (size_t index = 0; index < kN; ++index)
      {
        poly.c[index] = mod_q(static_cast<int64_t>(poly.c[index]) * 8347681);
      }
    }

    void to_mod_q(Poly &poly)
    {
      for (size_t index = 0; index < kN; ++index)
        poly.c[index] = mod_q(poly.c[index]);
    }

    void pointwise(Poly &out, const Poly &a, const Poly &b)
    {
      for (size_t index = 0; index < kN; ++index)
      {
        out.c[index] = mod_q(static_cast<int64_t>(a.c[index]) * b.c[index]);
      }
    }

    void add_mod_q(Poly &out, const Poly &a, const Poly &b)
    {
      for (size_t index = 0; index < kN; ++index)
      {
        int32_t sum = a.c[index] + b.c[index];
        if (sum >= kQ)
          sum -= kQ;
        out.c[index] = sum;
      }
    }

    void pack_simple(uint8_t *out, const int32_t *coefficients, size_t bits)
    {
      const size_t bytes = kN * bits / 8;
      memset(out, 0, bytes);
      size_t position = 0;
      for (size_t index = 0; index < kN; ++index)
      {
        uint32_t value = static_cast<uint32_t>(coefficients[index]);
        for (size_t bit = 0; bit < bits; ++bit)
        {
          if (((value >> bit) & 1u) != 0)
          {
            out[position >> 3] |= static_cast<uint8_t>(1u << (position & 7));
          }
          ++position;
        }
      }
    }

    void unpack_simple(int32_t *coefficients, const uint8_t *in, size_t bits)
    {
      size_t position = 0;
      for (size_t index = 0; index < kN; ++index)
      {
        uint32_t value = 0;
        for (size_t bit = 0; bit < bits; ++bit)
        {
          if (((in[position >> 3] >> (position & 7)) & 1u) != 0)
            value |= 1u << bit;
          ++position;
        }
        coefficients[index] = static_cast<int32_t>(value);
      }
    }

    void pack_delta(uint8_t *out, const int32_t *coefficients, size_t bits,
                    int32_t upper)
    {
      const size_t bytes = kN * bits / 8;
      memset(out, 0, bytes);
      size_t position = 0;
      for (size_t index = 0; index < kN; ++index)
      {
        uint32_t value = static_cast<uint32_t>(upper - coefficients[index]);
        for (size_t bit = 0; bit < bits; ++bit)
        {
          if (((value >> bit) & 1u) != 0)
          {
            out[position >> 3] |= static_cast<uint8_t>(1u << (position & 7));
          }
          ++position;
        }
      }
    }

    void unpack_delta(int32_t *coefficients, const uint8_t *in, size_t bits,
                      int32_t upper)
    {
      size_t position = 0;
      for (size_t index = 0; index < kN; ++index)
      {
        uint32_t value = 0;
        for (size_t bit = 0; bit < bits; ++bit)
        {
          if (((in[position >> 3] >> (position & 7)) & 1u) != 0)
            value |= 1u << bit;
          ++position;
        }
        coefficients[index] = upper - static_cast<int32_t>(value);
      }
    }

    bool expand_a(Workspace &workspace, const uint8_t rho[32])
    {
      for (size_t r = 0; r < kK; ++r)
      {
        for (size_t s = 0; s < kL; ++s)
        {
          uint8_t seed[34];
          memcpy(seed, rho, 32);
          seed[32] = static_cast<uint8_t>(s);
          seed[33] = static_cast<uint8_t>(r);
          if (!crypto_shake128(seed, sizeof(seed), workspace.stream,
                               sizeof(workspace.stream)))
          {
            return false;
          }
          Poly &poly = workspace.a[r][s];
          size_t filled = 0;
          for (size_t offset = 0;
               offset + 2 < sizeof(workspace.stream) && filled < kN; offset += 3)
          {
            const int32_t value =
                (static_cast<int32_t>(workspace.stream[offset + 2] & 0x7F) << 16) |
                (static_cast<int32_t>(workspace.stream[offset + 1]) << 8) |
                workspace.stream[offset];
            if (value < kQ)
              poly.c[filled++] = value;
          }
          if (filled != kN)
            return false;
        }
      }
      return true;
    }

    bool sample_eta(Poly &poly, const uint8_t rhoprime[64], uint32_t nonce)
    {
      uint8_t seed[66];
      memcpy(seed, rhoprime, 64);
      seed[64] = static_cast<uint8_t>(nonce);
      seed[65] = static_cast<uint8_t>(nonce >> 8);
      uint8_t stream[136 * 8];
      if (!crypto_shake256(seed, sizeof(seed), stream, sizeof(stream)))
        return false;
      size_t filled = 0;
      for (size_t index = 0; index < sizeof(stream) && filled < kN; ++index)
      {
        for (int half = 0; half < 2 && filled < kN; ++half)
        {
          const uint32_t nibble =
              half == 0 ? (stream[index] & 0x0F) : (stream[index] >> 4);
          if (nibble < 15)
          {
            poly.c[filled++] = 2 - static_cast<int32_t>(nibble % 5);
          }
        }
      }
      secure_zero(stream, sizeof(stream));
      return filled == kN;
    }

    bool expand_s(Workspace &workspace, const uint8_t rhoprime[64])
    {
      for (size_t index = 0; index < kL; ++index)
      {
        if (!sample_eta(workspace.s1[index], rhoprime, static_cast<uint32_t>(index)))
        {
          return false;
        }
      }
      for (size_t index = 0; index < kK; ++index)
      {
        if (!sample_eta(workspace.s2[index], rhoprime,
                        static_cast<uint32_t>(index + kL)))
        {
          return false;
        }
      }
      return true;
    }

    bool expand_mask(Poly mask[kL], const uint8_t rhoprime[64], uint32_t kappa)
    {
      for (size_t index = 0; index < kL; ++index)
      {
        uint8_t seed[66];
        memcpy(seed, rhoprime, 64);
        const uint32_t nonce = kappa + static_cast<uint32_t>(index);
        seed[64] = static_cast<uint8_t>(nonce);
        seed[65] = static_cast<uint8_t>(nonce >> 8);
        uint8_t packed[kZPackedBytes];
        if (!crypto_shake256(seed, sizeof(seed), packed, sizeof(packed)))
          return false;
        unpack_delta(mask[index].c, packed, 20, kGamma1);
      }
      return true;
    }

    bool sample_in_ball(Poly &challenge, const uint8_t c_tilde[kCTildeBytes])
    {
      uint8_t stream[8 + 1024];
      if (!crypto_shake256(c_tilde, kCTildeBytes, stream, sizeof(stream)))
      {
        return false;
      }
      memset(challenge.c, 0, sizeof(challenge.c));
      size_t position = 8;
      for (size_t index = kN - kTau; index < kN; ++index)
      {
        uint8_t value;
        do
        {
          if (position >= sizeof(stream))
            return false;
          value = stream[position++];
        } while (value > index);
        challenge.c[index] = challenge.c[value];
        const size_t bit_index = index + kTau - kN;
        const uint8_t sign = (stream[bit_index >> 3] >> (bit_index & 7)) & 1u;
        challenge.c[value] = sign != 0 ? -1 : 1;
      }
      return true;
    }

    void power2_round(int32_t coefficient, int32_t &high, int32_t &low)
    {
      high = (coefficient + (1 << (kD - 1)) - 1) >> kD;
      low = coefficient - (high << kD);
    }

    void decompose(int32_t coefficient, int32_t &high, int32_t &low)
    {
      const int32_t value = mod_q(coefficient);
      int32_t a1 = (value + 127) >> 7;
      a1 = (a1 * 1025 + (1 << 21)) >> 22;
      a1 &= 15;
      int32_t a0 = value - a1 * 2 * kGamma2;
      a0 -= (((kQ - 1) / 2 - a0) >> 31) & kQ;
      high = a1;
      low = a0;
    }

    int32_t high_bits(int32_t coefficient)
    {
      int32_t high, low;
      decompose(coefficient, high, low);
      return high;
    }

    int32_t low_bits(int32_t coefficient)
    {
      int32_t high, low;
      decompose(coefficient, high, low);
      return low;
    }

    bool make_hint(int32_t z, int32_t r)
    {
      return high_bits(r) != high_bits(mod_q(static_cast<int64_t>(r) + z));
    }

    int32_t use_hint(int32_t hint, int32_t coefficient)
    {
      int32_t high, low;
      decompose(coefficient, high, low);
      if (hint == 0)
        return high;
      return low > 0 ? ((high + 1) & 15) : ((high - 1) & 15);
    }

    void pack_public_key(uint8_t pk[kMlDsa87PublicKeySize], const uint8_t rho[32],
                         const Poly t1[kK])
    {
      memcpy(pk, rho, 32);
      for (size_t index = 0; index < kK; ++index)
      {
        pack_simple(pk + 32 + index * kT1PackedBytes, t1[index].c, 10);
      }
    }

    void unpack_public_key(uint8_t rho[32], Poly t1[kK],
                           const uint8_t pk[kMlDsa87PublicKeySize])
    {
      memcpy(rho, pk, 32);
      for (size_t index = 0; index < kK; ++index)
      {
        unpack_simple(t1[index].c, pk + 32 + index * kT1PackedBytes, 10);
      }
    }

    void pack_secret_key(uint8_t sk[kMlDsa87SecretKeySize], const uint8_t rho[32],
                         const uint8_t key[32], const uint8_t tr[64],
                         const Poly s1[kL], const Poly s2[kK],
                         const Poly t0[kK])
    {
      size_t offset = 0;
      memcpy(sk + offset, rho, 32);
      offset += 32;
      memcpy(sk + offset, key, 32);
      offset += 32;
      memcpy(sk + offset, tr, 64);
      offset += 64;
      for (size_t index = 0; index < kL; ++index)
      {
        pack_delta(sk + offset, s1[index].c, 3, kEta);
        offset += kEtaPackedBytes;
      }
      for (size_t index = 0; index < kK; ++index)
      {
        pack_delta(sk + offset, s2[index].c, 3, kEta);
        offset += kEtaPackedBytes;
      }
      for (size_t index = 0; index < kK; ++index)
      {
        pack_delta(sk + offset, t0[index].c, 13, 1 << (kD - 1));
        offset += kT0PackedBytes;
      }
    }

    void unpack_secret_key(const uint8_t sk[kMlDsa87SecretKeySize], uint8_t rho[32],
                           uint8_t key[32], uint8_t tr[64], Poly s1[kL],
                           Poly s2[kK], Poly t0[kK])
    {
      size_t offset = 0;
      memcpy(rho, sk + offset, 32);
      offset += 32;
      memcpy(key, sk + offset, 32);
      offset += 32;
      memcpy(tr, sk + offset, 64);
      offset += 64;
      for (size_t index = 0; index < kL; ++index)
      {
        unpack_delta(s1[index].c, sk + offset, 3, kEta);
        offset += kEtaPackedBytes;
      }
      for (size_t index = 0; index < kK; ++index)
      {
        unpack_delta(s2[index].c, sk + offset, 3, kEta);
        offset += kEtaPackedBytes;
      }
      for (size_t index = 0; index < kK; ++index)
      {
        unpack_delta(t0[index].c, sk + offset, 13, 1 << (kD - 1));
        offset += kT0PackedBytes;
      }
    }

    Workspace *allocate_workspace()
    {
      Workspace *workspace = static_cast<Workspace *>(malloc(sizeof(Workspace)));
      if (workspace != nullptr)
        memset(workspace, 0, sizeof(Workspace));
      return workspace;
    }

    void release_workspace(Workspace *workspace)
    {
      if (workspace == nullptr)
        return;
      secure_zero(workspace, sizeof(Workspace));
      free(workspace);
    }

    bool compute_mu(uint8_t mu[64], const uint8_t tr[64], const uint8_t *message,
                    size_t message_size)
    {
      if (message_size > 1024 * 1024)
        return false;
      const size_t total = 64 + message_size;
      uint8_t *buffer = static_cast<uint8_t *>(malloc(total == 0 ? 1 : total));
      if (buffer == nullptr)
        return false;
      memcpy(buffer, tr, 64);
      if (message_size != 0)
        memcpy(buffer + 64, message, message_size);
      const bool ok = crypto_shake256(buffer, total, mu, 64);
      secure_zero(buffer, total);
      free(buffer);
      return ok;
    }

    void pack_w1(uint8_t out[kK * kW1PackedBytes], const Poly w[kK], Poly &scratch)
    {
      for (size_t index = 0; index < kK; ++index)
      {
        for (size_t j = 0; j < kN; ++j)
          scratch.c[j] = high_bits(w[index].c[j]);
        pack_simple(out + index * kW1PackedBytes, scratch.c, 4);
      }
    }

    // Verification already holds r1 in [0, 15]; it must not be decomposed again.
    void pack_w1_values(uint8_t out[kK * kW1PackedBytes], const Poly w1[kK])
    {
      for (size_t index = 0; index < kK; ++index)
        pack_simple(out + index * kW1PackedBytes, w1[index].c, 4);
    }

    bool verify_hint_encoding(const uint8_t packed[kHintBytes], Poly h[kK])
    {
      memset(h, 0, sizeof(Poly) * kK);
      size_t index = 0;
      for (size_t r = 0; r < kK; ++r)
      {
        const size_t end = packed[kOmega + r];
        if (end < index || end > kOmega)
          return false;
        const size_t first = index;
        while (index < end)
        {
          if (index > first && packed[index - 1] >= packed[index])
            return false;
          h[r].c[packed[index]] = 1;
          ++index;
        }
      }
      for (size_t remaining = index; remaining < kOmega; ++remaining)
      {
        if (packed[remaining] != 0)
          return false;
      }
      return true;
    }

    bool pack_hint(uint8_t packed[kHintBytes], const Poly h[kK])
    {
      memset(packed, 0, kHintBytes);
      size_t index = 0;
      for (size_t r = 0; r < kK; ++r)
      {
        for (size_t j = 0; j < kN; ++j)
        {
          if (h[r].c[j] != 0)
          {
            if (index >= kOmega)
              return false;
            packed[index++] = static_cast<uint8_t>(j);
          }
        }
        packed[kOmega + r] = static_cast<uint8_t>(index);
      }
      return true;
    }

    bool compute_w(Workspace &workspace)
    {
      for (size_t r = 0; r < kK; ++r)
      {
        memset(&workspace.accumulator, 0, sizeof(Poly));
        for (size_t s = 0; s < kL; ++s)
        {
          pointwise(workspace.product, workspace.a[r][s], workspace.y[s]);
          add_mod_q(workspace.accumulator, workspace.accumulator, workspace.product);
        }
        inverse_ntt(workspace.accumulator);
        workspace.w[r] = workspace.accumulator;
      }
      return true;
    }

  } // namespace

  bool ml_dsa_87_keypair_from_seed(const uint8_t seed[kMlDsa87SeedSize],
                                   uint8_t public_key[kMlDsa87PublicKeySize],
                                   uint8_t secret_key[kMlDsa87SecretKeySize])
  {
    if (seed == nullptr || public_key == nullptr || secret_key == nullptr)
    {
      return false;
    }
    uint8_t expanded[2 + kMlDsa87SeedSize];
    memcpy(expanded, seed, kMlDsa87SeedSize);
    expanded[kMlDsa87SeedSize] = kK;
    expanded[kMlDsa87SeedSize + 1] = kL;
    uint8_t seedbuf[128];
    bool ok = crypto_shake256(expanded, sizeof(expanded), seedbuf, sizeof(seedbuf));
    secure_zero(expanded, sizeof(expanded));
    if (!ok)
      return false;
    const uint8_t *rho = seedbuf;
    const uint8_t *rhoprime = seedbuf + 32;
    const uint8_t *key = seedbuf + 96;

    Workspace *workspace = allocate_workspace();
    if (workspace == nullptr)
    {
      secure_zero(seedbuf, sizeof(seedbuf));
      return false;
    }
    ok = expand_a(*workspace, rho) && expand_s(*workspace, rhoprime);
    if (ok)
    {
      for (size_t index = 0; index < kL; ++index)
      {
        to_mod_q(workspace->s1[index]);
        ntt(workspace->s1[index]);
      }
      for (size_t r = 0; r < kK; ++r)
      {
        memset(&workspace->accumulator, 0, sizeof(Poly));
        for (size_t s = 0; s < kL; ++s)
        {
          pointwise(workspace->product, workspace->a[r][s], workspace->s1[s]);
          add_mod_q(workspace->accumulator, workspace->accumulator,
                    workspace->product);
        }
        inverse_ntt(workspace->accumulator);
        for (size_t j = 0; j < kN; ++j)
        {
          workspace->accumulator.c[j] =
              mod_q(static_cast<int64_t>(workspace->accumulator.c[j]) +
                    workspace->s2[r].c[j]);
        }
        for (size_t j = 0; j < kN; ++j)
        {
          int32_t high, low;
          power2_round(workspace->accumulator.c[j], high, low);
          workspace->t1[r].c[j] = high;
          workspace->cs2[r].c[j] = low; // t0
        }
      }
      pack_public_key(workspace->pk, rho, workspace->t1);
      uint8_t tr[64];
      ok = crypto_shake256(workspace->pk, kMlDsa87PublicKeySize, tr, sizeof(tr));
      if (ok)
      {
        ok = expand_s(*workspace, rhoprime);
        if (ok)
        {
          pack_secret_key(workspace->sk, rho, key, tr, workspace->s1,
                          workspace->s2, workspace->cs2);
          memcpy(public_key, workspace->pk, kMlDsa87PublicKeySize);
          memcpy(secret_key, workspace->sk, kMlDsa87SecretKeySize);
        }
      }
      secure_zero(tr, sizeof(tr));
    }
    release_workspace(workspace);
    secure_zero(seedbuf, sizeof(seedbuf));
    return ok;
  }

  bool ml_dsa_87_sign(const uint8_t secret_key[kMlDsa87SecretKeySize],
                      const uint8_t *message, size_t message_size,
                      const uint8_t rnd[32],
                      uint8_t signature[kMlDsa87SignatureSize])
  {
    if (secret_key == nullptr || signature == nullptr || rnd == nullptr ||
        (message == nullptr && message_size != 0))
    {
      return false;
    }
    Workspace *workspace = allocate_workspace();
    if (workspace == nullptr)
      return false;
    uint8_t rho[32], key[32], tr[64];
    unpack_secret_key(secret_key, rho, key, tr, workspace->s1, workspace->s2,
                      workspace->t0);
    bool ok = expand_a(*workspace, rho);
    uint8_t mu[64] = {};
    if (ok)
      ok = compute_mu(mu, tr, message, message_size);
    uint8_t rhoprime[64] = {};
    if (ok)
    {
      uint8_t seedbuf[128];
      memcpy(seedbuf, key, 32);
      memcpy(seedbuf + 32, rnd, 32);
      memcpy(seedbuf + 64, mu, 64);
      ok = crypto_shake256(seedbuf, sizeof(seedbuf), rhoprime, sizeof(rhoprime));
      secure_zero(seedbuf, sizeof(seedbuf));
    }
    if (ok)
    {
      for (size_t index = 0; index < kL; ++index)
      {
        to_mod_q(workspace->s1[index]);
        ntt(workspace->s1[index]);
      }
      for (size_t index = 0; index < kK; ++index)
      {
        to_mod_q(workspace->s2[index]);
        ntt(workspace->s2[index]);
        to_mod_q(workspace->t0[index]);
        ntt(workspace->t0[index]);
      }
    }
    uint32_t attempts = 0;
    uint32_t kappa = 0;
    while (ok)
    {
      if (attempts++ >= kMaxAttempts)
      {
        ok = false;
        break;
      }
      if (!expand_mask(workspace->y, rhoprime, kappa))
      {
        ok = false;
        break;
      }
      for (size_t index = 0; index < kL; ++index)
      {
        to_mod_q(workspace->y[index]);
        ntt(workspace->y[index]);
      }
      compute_w(*workspace);

      uint8_t w1_packed[kK * kW1PackedBytes];
      pack_w1(w1_packed, workspace->w, workspace->scratch);
      uint8_t c_tilde[kCTildeBytes];
      uint8_t hash_input[64 + kK * kW1PackedBytes];
      memcpy(hash_input, mu, 64);
      memcpy(hash_input + 64, w1_packed, sizeof(w1_packed));
      ok = crypto_shake256(hash_input, sizeof(hash_input), c_tilde,
                           sizeof(c_tilde));
      if (!ok)
        break;
      if (!sample_in_ball(workspace->scratch, c_tilde))
      {
        ok = false;
        break;
      }
      to_mod_q(workspace->scratch);
      ntt(workspace->scratch); // challenge, NTT domain

      bool rejected = false;
      for (size_t index = 0; index < kL; ++index)
      {
        pointwise(workspace->product, workspace->scratch, workspace->s1[index]);
        add_mod_q(workspace->accumulator, workspace->y[index],
                  workspace->product);
        inverse_ntt(workspace->accumulator);
        for (size_t j = 0; j < kN; ++j)
        {
          const int32_t value = centered(workspace->accumulator.c[j]);
          workspace->z[index].c[j] = value;
          if (value >= kGamma1 - kBeta || value <= -(kGamma1 - kBeta))
          {
            rejected = true;
          }
        }
      }
      if (rejected)
      {
        kappa += kL;
        continue;
      }
      for (size_t index = 0; index < kK; ++index)
      {
        pointwise(workspace->product, workspace->scratch, workspace->s2[index]);
        inverse_ntt(workspace->product);
        workspace->cs2[index] = workspace->product;
      }
      rejected = false;
      for (size_t index = 0; index < kK; ++index)
      {
        for (size_t j = 0; j < kN; ++j)
        {
          const int32_t difference =
              mod_q(static_cast<int64_t>(workspace->w[index].c[j]) -
                    workspace->cs2[index].c[j]);
          const int32_t low = low_bits(difference);
          if (low >= kGamma2 - kBeta || low <= -(kGamma2 - kBeta))
          {
            rejected = true;
          }
        }
      }
      if (rejected)
      {
        kappa += kL;
        continue;
      }
      rejected = false;
      for (size_t index = 0; index < kK; ++index)
      {
        pointwise(workspace->product, workspace->scratch, workspace->t0[index]);
        inverse_ntt(workspace->product);
        workspace->ct0[index] = workspace->product;
        for (size_t j = 0; j < kN; ++j)
        {
          const int32_t value = centered(workspace->product.c[j]);
          if (value >= kGamma2 || value <= -kGamma2)
            rejected = true;
        }
      }
      if (rejected)
      {
        kappa += kL;
        continue;
      }
      size_t hint_weight = 0;
      for (size_t index = 0; index < kK; ++index)
      {
        for (size_t j = 0; j < kN; ++j)
        {
          const int32_t r =
              mod_q(static_cast<int64_t>(workspace->w[index].c[j]) -
                    workspace->cs2[index].c[j] + workspace->ct0[index].c[j]);
          const int32_t neg_ct0 = centered(workspace->ct0[index].c[j]);
          const bool bit = make_hint(-neg_ct0, r);
          workspace->h[index].c[j] = bit ? 1 : 0;
          if (bit)
            ++hint_weight;
        }
      }
      if (hint_weight > kOmega)
      {
        kappa += kL;
        continue;
      }
      uint8_t hint_packed[kHintBytes];
      if (!pack_hint(hint_packed, workspace->h))
      {
        kappa += kL;
        continue;
      }
      size_t offset = 0;
      memcpy(signature + offset, c_tilde, kCTildeBytes);
      offset += kCTildeBytes;
      for (size_t index = 0; index < kL; ++index)
      {
        pack_delta(signature + offset, workspace->z[index].c, 20, kGamma1);
        offset += kZPackedBytes;
      }
      memcpy(signature + offset, hint_packed, kHintBytes);
      ok = true;
      break;
    }
    release_workspace(workspace);
    secure_zero(rhoprime, sizeof(rhoprime));
    secure_zero(mu, sizeof(mu));
    secure_zero(rho, sizeof(rho));
    secure_zero(key, sizeof(key));
    secure_zero(tr, sizeof(tr));
    if (!ok)
      secure_zero(signature, kMlDsa87SignatureSize);
    return ok;
  }

  bool ml_dsa_87_verify(const uint8_t public_key[kMlDsa87PublicKeySize],
                        const uint8_t *message, size_t message_size,
                        const uint8_t signature[kMlDsa87SignatureSize])
  {
    if (public_key == nullptr || signature == nullptr ||
        (message == nullptr && message_size != 0))
    {
      return false;
    }
    Workspace *workspace = allocate_workspace();
    if (workspace == nullptr)
      return false;
    uint8_t rho[32];
    unpack_public_key(rho, workspace->w, public_key); // w is reused as t1
    const uint8_t *c_tilde = signature;
    size_t offset = kCTildeBytes;
    for (size_t index = 0; index < kL; ++index)
    {
      unpack_delta(workspace->z[index].c, signature + offset, 20, kGamma1);
      offset += kZPackedBytes;
      for (size_t j = 0; j < kN; ++j)
      {
        const int32_t value = workspace->z[index].c[j];
        if (value >= kGamma1 - kBeta || value <= -(kGamma1 - kBeta))
        {
          release_workspace(workspace);
          return false;
        }
      }
    }
    if (!verify_hint_encoding(signature + offset, workspace->h))
    {
      release_workspace(workspace);
      return false;
    }
    bool ok = expand_a(*workspace, rho);
    uint8_t tr[64] = {};
    uint8_t mu[64] = {};
    if (ok)
      ok = crypto_shake256(public_key, kMlDsa87PublicKeySize, tr, sizeof(tr));
    if (ok)
      ok = compute_mu(mu, tr, message, message_size);
    if (ok)
      ok = sample_in_ball(workspace->scratch, c_tilde);
    if (ok)
    {
      to_mod_q(workspace->scratch);
      ntt(workspace->scratch);
      for (size_t index = 0; index < kK; ++index)
      {
        for (size_t j = 0; j < kN; ++j)
        {
          workspace->product.c[j] =
              mod_q(static_cast<int64_t>(workspace->w[index].c[j]) << kD);
        }
        ntt(workspace->product); // t1 * 2^d in NTT domain
        pointwise(workspace->ct0[index], workspace->scratch, workspace->product);

        memset(&workspace->accumulator, 0, sizeof(Poly));
        for (size_t s = 0; s < kL; ++s)
        {
          Poly &z_poly = workspace->cs2[index];
          for (size_t j = 0; j < kN; ++j)
          {
            z_poly.c[j] = mod_q(workspace->z[s].c[j]);
          }
          ntt(z_poly);
          pointwise(workspace->product, workspace->a[index][s], z_poly);
          add_mod_q(workspace->accumulator, workspace->accumulator,
                    workspace->product);
        }
        for (size_t j = 0; j < kN; ++j)
        {
          int32_t difference =
              workspace->accumulator.c[j] - workspace->ct0[index].c[j];
          if (difference < 0)
            difference += kQ;
          workspace->accumulator.c[j] = difference;
        }
        inverse_ntt(workspace->accumulator);
        for (size_t j = 0; j < kN; ++j)
        {
          workspace->accumulator.c[j] =
              use_hint(workspace->h[index].c[j], workspace->accumulator.c[j]);
        }
        workspace->w[index] = workspace->accumulator;
      }
      uint8_t w1_packed[kK * kW1PackedBytes];
      pack_w1_values(w1_packed, workspace->w);
      uint8_t hash_input[64 + kK * kW1PackedBytes];
      memcpy(hash_input, mu, 64);
      memcpy(hash_input + 64, w1_packed, sizeof(w1_packed));
      uint8_t computed[kCTildeBytes];
      if (crypto_shake256(hash_input, sizeof(hash_input), computed,
                          sizeof(computed)))
      {
        ok = memcmp(computed, c_tilde, sizeof(computed)) == 0;
        secure_zero(computed, sizeof(computed));
      }
      else
      {
        ok = false;
      }
    }
    release_workspace(workspace);
    secure_zero(rho, sizeof(rho));
    secure_zero(tr, sizeof(tr));
    secure_zero(mu, sizeof(mu));
    return ok;
  }

#if defined(HEXWALLET_HOST_TEST)
#include "tests/fixtures/MlDsa87Acvp.inc"

namespace {

int hex_digit(char value)
{
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

size_t decode_hex(const char *text, uint8_t *out, size_t capacity)
{
  const size_t length = strlen(text) / 2;
  if (length > capacity) return 0;
  for (size_t index = 0; index < length; ++index)
  {
    const int high = hex_digit(text[index * 2]);
    const int low = hex_digit(text[index * 2 + 1]);
    if (high < 0 || low < 0) return 0;
    out[index] = static_cast<uint8_t>((high << 4) | low);
  }
  return length;
}

// Rebuilds t1 from the secret key so an ACVP signature can be verified against
// the public key that belongs to its signing key. Host tests only.
bool derive_public_key_from_secret(const uint8_t sk[kMlDsa87SecretKeySize],
                                   uint8_t pk[kMlDsa87PublicKeySize])
{
  Workspace *workspace = allocate_workspace();
  if (workspace == nullptr) return false;
  uint8_t rho[32], key[32], tr[64];
  unpack_secret_key(sk, rho, key, tr, workspace->s1, workspace->s2,
                    workspace->t0);
  bool ok = expand_a(*workspace, rho);
  if (ok)
  {
    for (size_t index = 0; index < kL; ++index)
    {
      to_mod_q(workspace->s1[index]);
      ntt(workspace->s1[index]);
    }
    for (size_t r = 0; r < kK; ++r)
    {
      memset(&workspace->accumulator, 0, sizeof(Poly));
      for (size_t s = 0; s < kL; ++s)
      {
        pointwise(workspace->product, workspace->a[r][s], workspace->s1[s]);
        add_mod_q(workspace->accumulator, workspace->accumulator,
                  workspace->product);
      }
      inverse_ntt(workspace->accumulator);
      for (size_t j = 0; j < kN; ++j)
      {
        const int32_t t =
            mod_q(static_cast<int64_t>(workspace->accumulator.c[j]) +
                  workspace->s2[r].c[j]);
        int32_t high, low;
        power2_round(t, high, low);
        workspace->t1[r].c[j] = high;
      }
    }
    pack_public_key(pk, rho, workspace->t1);
  }
  release_workspace(workspace);
  secure_zero(rho, sizeof(rho));
  secure_zero(key, sizeof(key));
  secure_zero(tr, sizeof(tr));
  return ok;
}

}  // namespace
#endif

bool run_ml_dsa_87_self_tests()
{
#if !defined(HEXWALLET_HOST_TEST)
  return true;
#else
  uint8_t seed[32];
  uint8_t expected_pk[kMlDsa87PublicKeySize];
  uint8_t expected_sk[kMlDsa87SecretKeySize];
  if (decode_hex(kMlDsa87AcvpSeedHex, seed, sizeof(seed)) != sizeof(seed) ||
      decode_hex(kMlDsa87AcvpPkHex, expected_pk, sizeof(expected_pk)) != sizeof(expected_pk) ||
      decode_hex(kMlDsa87AcvpSkHex, expected_sk, sizeof(expected_sk)) != sizeof(expected_sk))
  {
    return false;
  }
  uint8_t public_key[kMlDsa87PublicKeySize];
  uint8_t secret_key[kMlDsa87SecretKeySize];
  bool ok = ml_dsa_87_keypair_from_seed(seed, public_key, secret_key) &&
            memcmp(public_key, expected_pk, sizeof(public_key)) == 0 &&
            memcmp(secret_key, expected_sk, sizeof(secret_key)) == 0;

  uint8_t sign_sk[kMlDsa87SecretKeySize];
  uint8_t message[4096];
  uint8_t context[256];
  uint8_t expected_signature[kMlDsa87SignatureSize];
  const size_t message_size = decode_hex(kMlDsa87AcvpMessageHex, message, sizeof(message));
  const size_t context_size = decode_hex(kMlDsa87AcvpContextHex, context, sizeof(context));
  if (message_size == 0 ||
      decode_hex(kMlDsa87AcvpSignSkHex, sign_sk, sizeof(sign_sk)) != sizeof(sign_sk) ||
      decode_hex(kMlDsa87AcvpSignatureHex, expected_signature,
                 sizeof(expected_signature)) != sizeof(expected_signature))
  {
    return false;
  }
  uint8_t formatted[2 + 256 + 4096];
  formatted[0] = 0;
  formatted[1] = static_cast<uint8_t>(context_size);
  memcpy(formatted + 2, context, context_size);
  memcpy(formatted + 2 + context_size, message, message_size);
  const size_t formatted_size = 2 + context_size + message_size;
  uint8_t rnd[32] = {};
  uint8_t signature[kMlDsa87SignatureSize];
  ok = ok && ml_dsa_87_sign(sign_sk, formatted, formatted_size, rnd, signature) &&
       memcmp(signature, expected_signature, sizeof(signature)) == 0;

  uint8_t derived_pk[kMlDsa87PublicKeySize];
  ok = ok && derive_public_key_from_secret(sign_sk, derived_pk) &&
       ml_dsa_87_verify(derived_pk, formatted, formatted_size,
                        expected_signature);

  static const uint8_t local_message[] = "hexwallet ml-dsa-87";
  uint8_t local_signature[kMlDsa87SignatureSize];
  uint8_t local_rnd[32] = {0x5a};
  ok = ok && ml_dsa_87_sign(secret_key, local_message, sizeof(local_message) - 1,
                            local_rnd, local_signature) &&
       ml_dsa_87_verify(public_key, local_message, sizeof(local_message) - 1,
                        local_signature);
  local_signature[17] ^= 0x01;
  ok = ok && !ml_dsa_87_verify(public_key, local_message,
                               sizeof(local_message) - 1, local_signature);
  ok = ok && !ml_dsa_87_verify(public_key, local_message,
                               sizeof(local_message) - 2, local_signature);

  secure_zero(sign_sk, sizeof(sign_sk));
  secure_zero(expected_sk, sizeof(expected_sk));
  secure_zero(public_key, sizeof(public_key));
  secure_zero(secret_key, sizeof(secret_key));
  secure_zero(signature, sizeof(signature));
  secure_zero(local_signature, sizeof(local_signature));
  return ok;
#endif
}

}
