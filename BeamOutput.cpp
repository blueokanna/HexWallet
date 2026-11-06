#include "BeamOutput.h"
#include <cstring>
#include "src/beam/WalletKeys.h"

namespace hexwallet {
namespace {
using Proof = ECC::RangeProof::Confidential;
constexpr uint32_t kSchemeV3 = 3u << 24;
constexpr uint32_t kFork6Proof = 1;

bool supported(const BeamCoin &coin) {
  return coin.groth && coin.subkey < (1u << 24) &&
         (coin.type == BeamCoinType::Regular || coin.type == BeamCoinType::Change);
}

}
namespace beam_keys {
void master_key(const uint8_t *seed, ECC::HKdf &master) {
  ECC::NoLeak<ECC::Hash::Value> hash;
  ECC::Hash::Processor() << beam::Blob(seed, 64) >> hash.V;
  master.Generate(hash.V);
}

ECC::Key::ID key_id(const BeamCoin &coin) {
  return ECC::Key::ID(coin.index, uint32_t(coin.type), kSchemeV3 | coin.subkey);
}

void switch_commitment(ECC::HKdf &master, const BeamCoin &coin, ECC::Scalar::Native &sk,
                       ECC::Point &commitment) {
  const ECC::Key::ID kid = key_id(coin);
  ECC::HKdf child;
  child.GenerateChild(master, coin.subkey);
  ECC::Hash::Value hash;
  ECC::Hash::Processor() << "kidv-1" << kid.m_Idx << kid.m_Type.V << kid.m_SubIdx << coin.groth >> hash;
  child.DeriveKey(sk, hash);
  const auto &ctx = ECC::Context::get();
  ECC::Point::Native comm = ctx.G * sk;
  comm += ctx.H * coin.groth;
  const ECC::Point::Native switch_point = ctx.J * sk;
  ECC::Scalar::Native delta;
  ECC::Oracle() << comm << switch_point >> delta;
  sk += delta;
  comm += ctx.G * delta;
  commitment = comm;
}

}
using beam_keys::master_key;
using beam_keys::switch_commitment;
namespace {
void recovery_seed(ECC::HKdf &master, const ECC::Point &point, ECC::uintBig &seed) {
  ECC::Hash::Value hash;
  ECC::Hash::Processor() << point >> hash;
  ECC::Scalar::Native tag;
  master.DerivePKey(tag, hash);
  ECC::Hash::Processor() << tag >> seed;
}

void start_oracle(ECC::Oracle &oracle, const ECC::Point &point) {
  oracle << uint64_t(0) << point << false;
}

void encode(const Proof &p, const ECC::Point &comm, BeamOutput &out) {
  memcpy(out.commitment_x, comm.m_X.m_pData, 32);
  out.flags = 4 | comm.m_Y;
  uint8_t *cursor = out.proof;
  uint16_t signs = 0;
  auto word = [&](const ECC::uintBig &v) { memcpy(cursor, v.m_pData, 32); cursor += 32; };
  auto point = [&](const ECC::Point &v, unsigned bit) { word(v.m_X); signs |= uint16_t(v.m_Y) << bit; };
  point(p.m_Part1.m_A, 12);
  point(p.m_Part1.m_S, 13);
  point(p.m_Part2.m_T1, 14);
  point(p.m_Part2.m_T2, 15);
  word(p.m_Part3.m_TauX.m_Value);
  word(p.m_Mu.m_Value);
  word(p.m_tDot.m_Value);
  for (unsigned i = 0; i < 6; ++i)
    for (unsigned j = 0; j < 2; ++j) point(p.m_P_Tag.m_pLR[i][j], 2*i+j);
  for (const auto &s : p.m_P_Tag.m_pCondensed) word(s.m_Value);
  cursor[0] = uint8_t(signs);
  cursor[1] = uint8_t(signs >> 8);
}

bool decode_verified(const BeamOutput &in, ECC::Point &comm, Proof &p) {
  // Admission requires a completed verification, never a deferred batch.
  if (ECC::InnerProduct::BatchContext::current()) return false;
  if ((in.flags & 0xfe) != 4) return false;
  memcpy(comm.m_X.m_pData, in.commitment_x, 32);
  comm.m_Y = in.flags & 1;
  ECC::Point::Native point_comm;
  if (comm.m_Y > 1 || !point_comm.ImportNnz(comm)) return false;
  const auto *cursor = in.proof;
  const unsigned signs = cursor[672] | unsigned(cursor[673]) << 8;
  auto word = [&](ECC::uintBig &v) { memcpy(v.m_pData, cursor, 32); cursor += 32; };
  auto point = [&](ECC::Point &v, unsigned bit) { word(v.m_X); v.m_Y = (signs >> bit) & 1; };
  auto scalar = [&](ECC::Scalar &s) { word(s.m_Value); return s.IsValid(); };
  point(p.m_Part1.m_A, 12);
  point(p.m_Part1.m_S, 13);
  point(p.m_Part2.m_T1, 14);
  point(p.m_Part2.m_T2, 15);
  if (!scalar(p.m_Part3.m_TauX) || !scalar(p.m_Mu) || !scalar(p.m_tDot)) return false;
  for (unsigned i = 0; i < 6; ++i)
    for (unsigned j = 0; j < 2; ++j) point(p.m_P_Tag.m_pLR[i][j], 2*i+j);
  for (auto &s : p.m_P_Tag.m_pCondensed) if (!scalar(s)) return false;
  ECC::Oracle oracle;
  start_oracle(oracle, comm);
  return p.IsValid(point_comm, kFork6Proof, oracle);
}
}

bool beam_create_output(const uint8_t seed[64], const BeamCoin &coin, BeamOutput &out) {
  out = {};
  if (!seed || !supported(coin)) return false;
  try {
    ECC::HKdf master;
    master_key(seed, master);
    ECC::Scalar::Native blind;
    ECC::Point comm;
    switch_commitment(master, coin, blind, comm);
    ECC::RangeProof::Params::Create params{};
    recovery_seed(master, comm, params.m_Seed.V);
    params.m_Value = coin.groth;
    struct { uint8_t asset[4]; ECC::Key::ID::Packed kid; } packed{};
    static_assert(sizeof(packed) == 20);
    packed.kid = beam_keys::key_id(coin);
    params.m_Blob = beam::Blob(&packed, sizeof(packed));
    ECC::Oracle oracle;
    start_oracle(oracle, comm);
    Proof proof;
    proof.Create(blind, params, kFork6Proof, oracle);
    BeamOutput checked;
    encode(proof, comm, checked);
    if (!beam_verify_output(checked)) return false;
    out = checked;
    return true;
  } catch (const std::exception &) { return false; }
}

bool beam_verify_output(const BeamOutput &in) {
  try {
    ECC::Point comm;
    Proof proof;
    return decode_verified(in, comm, proof);
  } catch (const std::exception &) { return false; }
}

bool beam_recover_output(const uint8_t seed[64], const BeamOutput &in, BeamCoin &out) {
  out = {};
  if (!seed) return false;
  try {
    ECC::Point comm;
    Proof proof;
    if (!decode_verified(in, comm, proof)) return false;
    ECC::HKdf master;
    master_key(seed, master);
    ECC::RangeProof::Params::Recover params{};
    recovery_seed(master, comm, params.m_Seed.V);
    ECC::Key::ID::Packed packed;
    params.m_Blob = beam::Blob(&packed, sizeof(packed));
    ECC::Oracle oracle;
    start_oracle(oracle, comm);
    if (!proof.Recover(kFork6Proof, oracle, params)) return false;
    ECC::Key::ID kid;
    kid = packed;
    if (kid.m_SubIdx >> 24 != 3) return false;
    BeamCoin coin{kid.m_Idx, BeamCoinType(kid.m_Type.V), kid.m_SubIdx & 0xffffff, params.m_Value};
    if (!supported(coin)) return false;
    ECC::Scalar::Native blind;
    ECC::Point expected;
    switch_commitment(master, coin, blind, expected);
    if (expected != comm) return false;
    out = coin;
    return true;
  } catch (const std::exception &) { return false; }
}
}
