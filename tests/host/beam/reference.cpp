// Standalone interoperability oracle. Compile against BeamMW/beam
// 90a8be3ba2bed3e3adac748867658e9381b3f462, outside the firmware build.
#include "core/ecc_native.h"
#include <cstdio>
#include <cstring>

#include "yas/binary_iarchive.hpp"
#include "yas/mem_streams.hpp"
#include "yas/binary_oarchive.hpp"
#include "yas/types/std/vector.hpp"
#include "yas/types/std/pair.hpp"
#include "yas/types/utility/enum.hpp"
#include "wallet/core/base58.h"

// Reproduce GenerateRegularNewToken for the public test seed, using the
// upstream KDF, compacted YAS serializer and wallet Base58 implementation.
static std::string regular_token() {
  uint8_t seed[64]{};
  ECC::Hash::Value seed_hash;
  ECC::Hash::Processor() << beam::Blob(seed, sizeof(seed)) >> seed_hash;
  ECC::HKdf master;
  master.Generate(seed_hash);
  auto peer = [&](ECC::Key::Type type) {
    ECC::Hash::Value id;
    ECC::Key::ID(1, type).get_Hash(id);
    ECC::Scalar::Native sk;
    master.DeriveKey(sk, id);
    ECC::Point p = ECC::Point::Native(ECC::Context::get().G * sk);
    return p.m_X;
  };
  auto bbs = peer(ECC::Key::Type::Bbs), ep = peer(ECC::Key::Type::EndPoint);
  uint64_t word;
  bbs.ExportWord<0>(word);
  beam::uintBigFor<uint64_t>::Type channel;
  channel = word % 1024;
  std::vector<uint8_t> addr(channel.m_pData, channel.m_pData + sizeof(channel));
  addr.insert(addr.end(), bbs.m_pData, bbs.m_pData + sizeof(bbs));
  enum class Id : uint8_t { Type=0, Addr=7, Permanent=8, Endpoint=21 };
  enum class TxType : uint8_t { Simple=0 };
  auto pack = [](auto const &...fields) {
    yas::mem_ostream stream;
    yas::binary_oarchive<yas::mem_ostream,yas::binary|yas::no_header|yas::elittle|yas::compacted> ar(stream);
    ((ar & fields), ...);
    auto buf = stream.get_intrusive_buffer();
    return std::vector<uint8_t>(buf.data, buf.data + buf.size);
  };
  std::vector<std::pair<Id,std::vector<uint8_t>>> params = {
    {Id::Type,pack(TxType::Simple)}, {Id::Addr,addr}, {Id::Permanent,pack(true)},
    {Id::Endpoint,{ep.m_pData,ep.m_pData+sizeof(ep)}}};
  return beam::wallet::EncodeToBase58(pack(uint8_t(128),false,params));
}

static bool verify_output(const uint8_t *wire, ECC::Point::Native &c) {
  if ((wire[0] & 0xfe) != 4) return false;
  ECC::Point commitment;
  memcpy(commitment.m_X.m_pData, wire + 1, 32);
  commitment.m_Y = wire[0] & 1;
  if (!c.ImportNnz(commitment)) return false;
  ECC::RangeProof::Confidential p;
  // Layout in hw_crypto/keykeeper.h: RangeProof_Packed.
  const uint8_t *body = wire + 33;
  unsigned signs = body[672] | (unsigned(body[673]) << 8);
  auto pt = [&](ECC::Point &q, unsigned word, unsigned bit) {
    memcpy(q.m_X.m_pData, body + 32 * word, 32);
    q.m_Y = (signs >> bit) & 1;
  };
  auto scalar = [&](ECC::Scalar &s, unsigned word) {
    memcpy(s.m_Value.m_pData, body + 32 * word, 32);
    return s.IsValid();
  };
  pt(p.m_Part1.m_A, 0, 12);
  pt(p.m_Part1.m_S, 1, 13);
  pt(p.m_Part2.m_T1, 2, 14);
  pt(p.m_Part2.m_T2, 3, 15);
  if (!scalar(p.m_Part3.m_TauX, 4) || !scalar(p.m_Mu, 5) || !scalar(p.m_tDot, 6)) return false;
  for (unsigned i = 0; i < 12; ++i) pt(p.m_P_Tag.m_pLR[i/2][i%2], 7 + i, i);
  if (!scalar(p.m_P_Tag.m_pCondensed[0], 19) || !scalar(p.m_P_Tag.m_pCondensed[1], 20)) return false;
  ECC::Oracle oracle;
  oracle << uint64_t(0) << commitment << false;
  return p.IsValid(c, 1, oracle);
}

int main(int argc, char **argv) {
  if (argc == 2 && !strcmp(argv[1], "--regular-token")) { puts(regular_token().c_str()); return 0; }
  if (argc != 3) return 2;
  std::ifstream input(argv[1], std::ios::binary), tx(argv[2], std::ios::binary);
  uint8_t funded[707], wire[2048];
  if (!input.read(reinterpret_cast<char *>(funded), sizeof(funded)) || input.peek() != EOF || !tx) return 1;
  tx.read(reinterpret_cast<char *>(wire), sizeof(wire));
  size_t n = size_t(tx.gcount());
  // The regression transaction has one input, two outputs and one standard kernel.
  // Require sufficient bytes for all three compact uint64 values before handing
  // them to YAS (the upstream memory stream uses an unchecked getch).
  constexpr size_t kernel = 4 + 33 + 4 + 2*707 + 4;
  if (n < kernel + 97 + 3 + 32 || n > kernel + 97 + 27 + 32 ||
      memcmp(wire, "\x00\x00\x00\x01", 4) || wire[4] != (funded[0] & 1) ||
      memcmp(wire + 5, funded + 1, 32) || memcmp(wire+37,"\x00\x00\x00\x02",4) ||
      memcmp(wire + kernel - 4,"\x00\x00\x00\x01",4)) return 1;
  ECC::Point::Native owned, first, second;
  if (!verify_output(funded, owned) || !verify_output(wire + 41, first) ||
      !verify_output(wire + 748, second) || !(ECC::Point(first) < ECC::Point(second))) return 1;
  const uint8_t *k = wire + kernel;
  if ((k[0] & 0xee) != 14) return 1;
  ECC::Point excess;
  excess.m_Y = k[0] & 1;
  memcpy(excess.m_X.m_pData,k+1,32);
  ECC::Signature sig;
  sig.m_NoncePub.m_Y = (k[0] >> 4) & 1;
  memcpy(sig.m_NoncePub.m_X.m_pData,k+33,32);
  memcpy(sig.m_k.m_Value.m_pData,k+65,32);
  // Padding is only for safe decoding of malformed input; exact consumed
  // length must still agree with the original transaction.
  uint8_t ordinals[27]{};
  size_t encoded = n - kernel - 97 - 32;
  memcpy(ordinals, k+97, encoded);
  yas::mem_istream stream(ordinals, sizeof(ordinals));
  yas::binary_iarchive<yas::mem_istream, yas::binary|yas::no_header|yas::elittle|yas::compacted> ar(stream);
  uint64_t fee, low, delta;
  ar & fee & low & delta;
  if (sizeof(ordinals) - stream.get_intrusive_buffer().size != encoded ||
      fee != 100000 || low != 4000000 || delta != 100) return 1;
  ECC::Hash::Value id;
  ECC::Hash::Processor() << fee << low << uint64_t(low+delta) << excess << uint64_t(0) << uint8_t(0) << true >> id;
  ECC::Point::Native pub;
  if (!pub.ImportNnz(excess) || !sig.m_k.IsValid() || !sig.IsValid(id, pub)) return 1;
  ECC::Scalar offset;
  memcpy(offset.m_Value.m_pData,wire+n-32,32);
  if (!offset.IsValid()) return 1;
  ECC::Point::Native sum = first + second;
  sum += pub;
  sum += ECC::Context::get().G * ECC::Scalar::Native(offset);
  sum += ECC::Context::get().H * fee;
  if (!(sum == owned)) return 1;
  puts("upstream-beam-rangeproof-kernel-balance=pass");
  return 0;
}
