// Host-only ABI subset for compiling the pinned Monero BP+ sources.
// No HexWallet implementation is linked into the reference executable.
#pragma once
#include <algorithm>
#include <array>
#include <cassert>
#include <cstring>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
extern "C" {
#include "crypto/crypto-ops.h"
#include "crypto/keccak.h"
}
namespace rct {
struct key {
  unsigned char bytes[32];
  unsigned char &operator[](size_t i) { return bytes[i]; }
  const unsigned char &operator[](size_t i) const { return bytes[i]; }
};
using keyV = std::vector<key>;
inline bool operator==(const key &a, const key &b) { return !memcmp(a.bytes,b.bytes,32); }
inline bool operator!=(const key &a, const key &b) { return !(a==b); }
inline key zero() { return {}; }
inline key identity() { return {{1}}; }
inline key copy(const key &k) { return k; }
inline constexpr key G = {{0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66}};
inline constexpr key H = {{0x8b,0x65,0x59,0x70,0x15,0x37,0x99,0xaf,0x2a,0xea,0xdc,0x9f,0xf1,0xad,0xd0,0xea,0x6c,0x72,0x51,0xd5,0x41,0x54,0xcf,0xa9,0x2c,0x17,0x3a,0x0d,0xd3,0x9c,0x1f,0x94}};
inline constexpr key INV_EIGHT = {{0x79,0x2f,0xdc,0xe2,0x29,0xe5,0x06,0x61,0xd0,0xda,0x1c,0x7d,0xb3,0x9d,0xd3,0x07,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x06}};
struct BulletproofPlus {
  keyV V;
  key A,A1,B,r1,s1,d1;
  keyV L,R;
  BulletproofPlus() = default;
  BulletproofPlus(keyV v,key a,key a1,key b,key r,key s,key d,keyV l,keyV rr)
      : V(std::move(v)), A(a), A1(a1), B(b), r1(r), s1(s), d1(d), L(std::move(l)), R(std::move(rr)) {}
};
}
namespace crypto {
inline rct::key cn_fast_hash(const void *p, size_t n) {
  rct::key h; keccak(static_cast<const uint8_t*>(p),n,h.bytes,32); return h;
}
}
