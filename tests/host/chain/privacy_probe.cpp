// Test-only binary bridge. Never linked into the firmware command dispatcher.
#include <cstdio>
#include <cstring>
#include <vector>
#include "RyoMlsag.h"
#include "RyoBulletproof.h"
#include "RyoTransaction.h"
#include "ZanoClsag.h"
#include "WalletSecurity.h"
using namespace hexwallet;

namespace {
bool read_file(const char *path, std::vector<uint8_t> &out) {
  FILE *file = fopen(path, "rb");
  if (!file) return false;
  uint8_t block[1024]; size_t n;
  while ((n = fread(block, 1, sizeof(block), file)) != 0) {
    if (out.size() + n > kRyoMaxTxBytes) { fclose(file); return false; }
    out.insert(out.end(), block, block + n);
  }
  const bool ok = ferror(file) == 0; fclose(file); return ok;
}
bool write_file(const char *path, const std::vector<uint8_t> &out) {
  FILE *file = fopen(path, "wb");
  if (!file) return false;
  const bool ok = fwrite(out.data(), 1, out.size(), file) == out.size();
  return fclose(file) == 0 && ok;
}
uint32_t le32(const uint8_t *p) {
  return uint32_t(p[0]) | (uint32_t(p[1]) << 8) |
      (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
void append(std::vector<uint8_t> &v, const uint8_t *p, size_t n) {
  v.insert(v.end(), p, p + n);
}
bool erased(const void *p, size_t n) {
  const auto *bytes = static_cast<const uint8_t *>(p);
  uint8_t any = 0; for (size_t i = 0; i < n; ++i) any |= bytes[i];
  return any == 0;
}
void print_hex(const char *name, const uint8_t *p, size_t size) {
  printf("%s=", name);
  for (size_t i = 0; i < size; ++i) printf("%02x", p[i]);
  puts("");
}
}  // namespace

int privacy_probe(int argc, char **argv) {
  if (argc == 3 && !strcmp(argv[1], "privacy-ryo-parser-stress")) {
    std::vector<uint8_t> original;
    if (!read_file(argv[2], original) || original.empty()) return 2;
    auto check = [](const uint8_t *bytes, size_t size, bool truncated) {
      struct Guarded { uint64_t before; RyoTransactionView tx; uint64_t after; } guarded;
      memset(&guarded, 0xa5, sizeof(guarded));
      const auto error = ryo_parse_transaction(bytes, size, &guarded.tx);
      if (guarded.before != UINT64_C(0xa5a5a5a5a5a5a5a5) || guarded.after != guarded.before) return false;
      if (error != RyoTxError::Ok) return erased(&guarded.tx, sizeof(guarded.tx));
      if (truncated || guarded.tx.size != size) return false;
      RyoTransactionHashes digest;
      return ryo_transaction_hashes(bytes, size, &digest) == RyoTxError::Ok;
    };
    for (size_t size = 0; size < original.size(); ++size)
      if (!check(original.data(), size, true)) return 3;
    uint32_t random = 0x352c14ab;
    auto next = [&random]() { random ^= random << 13; random ^= random >> 17; random ^= random << 5; return random; };
    std::vector<uint8_t> changed = original;
    for (size_t test = 0; test < 10000; ++test) {
      changed = original;
      for (size_t j = 0; j < 1 + test % 4; ++j) changed[next() % changed.size()] ^= uint8_t(next());
      if (!check(changed.data(), changed.size(), false)) return 3;
    }
    for (size_t test = 0; test < 1000; ++test) {
      changed.resize(next() % 1024);
      for (auto &byte : changed) byte = uint8_t(next());
      if (!check(changed.data(), changed.size(), false)) return 3;
    }
    puts("ryo-parser-stress=pass");
    return 0;
  }
  if (argc >= 3 && (!strcmp(argv[1], "privacy-ryo-transaction") ||
                    !strcmp(argv[1], "privacy-ryo-parse"))) {
    std::vector<uint8_t> input;
    if (!read_file(argv[2], input)) return 2;
    RyoTransactionView tx;
    memset(&tx, 0xa5, sizeof(tx));
    auto error = ryo_parse_transaction(input.data(), input.size(), &tx);
    if (error != RyoTxError::Ok && !erased(&tx, sizeof(tx))) return 3;
    printf("parse=%u\n", static_cast<unsigned>(error));
    RyoTransactionHashes hashes;
    memset(&hashes, 0xa5, sizeof(hashes));
    const auto hashed = ryo_transaction_hashes(input.data(), input.size(), &hashes);
    if (hashed != error || (hashed != RyoTxError::Ok && !erased(&hashes, sizeof(hashes)))) return 3;
    if (error != RyoTxError::Ok) return 1;
    print_hex("prefix", hashes.prefix, 32); print_hex("base", hashes.base, 32);
    print_hex("prunable", hashes.prunable, 32); print_hex("transaction", hashes.transaction, 32);
    print_hex("signing", hashes.signing, 32);
    if (!strcmp(argv[1], "privacy-ryo-parse")) return 0;
    error = ryo_transaction_verify_semantics(input.data(), input.size());
    printf("semantics=%u\n", static_cast<unsigned>(error));
    if (error != RyoTxError::Ok) return 1;
    if (argc == 4) {
      std::vector<uint8_t> encoded;
      if (!read_file(argv[3], encoded) || encoded.size() != size_t(tx.input_count) * tx.ring_size * 64) return 2;
      std::vector<RyoRingMember> ring(tx.ring_size);
      for (size_t i = 0; i < tx.input_count; ++i) {
        memcpy(ring.data(), encoded.data() + i * tx.ring_size * 64, tx.ring_size * 64);
        error = ryo_transaction_verify_input(input.data(), input.size(), i, ring.data(), ring.size());
        if (error != RyoTxError::Ok) { printf("input=%zu error=%u\n", i, static_cast<unsigned>(error)); return 1; }
      }
      puts("mlsag=pass");
    }
    return 0;
  }
  if (argc == 3 && !strcmp(argv[1], "privacy-bulletproof")) {
    std::vector<uint8_t> input;
    if (!read_file(argv[2], input) || input.empty() || input[0] < 1 || input[0] > 16) return 2;
    const size_t count = input[0], base = 1 + count * 32;
    if (input.size() < base + 290) return 2;
    const uint8_t *p = input.data() + base;
    const size_t rounds = p[192];
    if (rounds < 6 || rounds > 10 || input.size() != base + 290 + rounds * 64 ||
        p[193 + rounds * 32] != rounds) return 2;
    const RyoBulletproofView proof{input.data() + 1, count, p, p + 32, p + 64, p + 96,
        p + 128, p + 160, p + 193, p + 194 + rounds * 32, rounds,
        p + 194 + rounds * 64, p + 226 + rounds * 64, p + 258 + rounds * 64};
    return ryo_bulletproof_verify(proof) ? 0 : 1;
  }
  if (argc != 4 || (strcmp(argv[1], "privacy-sign") && strcmp(argv[1], "privacy-verify"))) return 2;
  const bool signing = !strcmp(argv[1], "privacy-sign");
  std::vector<uint8_t> input, signature, output;
  if (!read_file(argv[2], input) || input.size() < 12) return 2;
  if (!signing && !read_file(argv[3], signature)) return 2;
  const bool ryo = !memcmp(input.data(), "HRYO", 4);
  if (!ryo && memcmp(input.data(), "HZAN", 4)) return 2;
  const size_t n = le32(input.data() + 4), index = le32(input.data() + 8);
  if (!n || n > (ryo ? kRyoMaxRingSize : kZanoMaxRingSize)) return 2;
  const size_t header = ryo ? 172 : 236, member_size = ryo ? 64 : 96;
  if (input.size() != header + member_size * n) return 2;
  const uint8_t *message = input.data() + 12, *entropy = message + 32, *spend = entropy + 32;
  bool ok = false;
  if (ryo) {
    std::vector<RyoRingMember> ring(n);
    memcpy(ring.data(), input.data() + header, n * sizeof(RyoRingMember));
    RyoMlsagSignature sig{};
    if (signing) {
      memset(&sig, 0xa5, sizeof(sig));
      ok = ryo_mlsag_sign(message, ring.data(), n, index, spend, spend + 32,
                           spend + 64, entropy, &sig);
      if (!ok && !erased(&sig, sizeof(sig))) return 3;
    } else {
      if (signature.size() != 64 + n * 64) return 2;
      sig.ring_size = static_cast<uint16_t>(n);
      memcpy(sig.challenge, signature.data(), 32);
      memcpy(sig.key_image, signature.data() + 32, 32);
      memcpy(sig.responses, signature.data() + 64, n * 64);
      ok = ryo_mlsag_verify(message, ring.data(), n, spend + 64, sig);
    }
    if (ok && signing) {
      append(output, sig.challenge, 32); append(output, sig.key_image, 32);
      append(output, &sig.responses[0][0][0], n * 64);
    }
    secure_zero(&sig, sizeof(sig));
  } else {
    std::vector<ZanoRingMember> ring(n);
    memcpy(ring.data(), input.data() + header, n * sizeof(ZanoRingMember));
    ZanoClsagSignature sig{};
    if (signing) {
      memset(&sig, 0xa5, sizeof(sig));
      ok = zano_clsag_ggx_sign(message, ring.data(), n, index, spend, spend + 32,
          spend + 64, spend + 96, spend + 128, entropy, &sig);
      if (!ok && !erased(&sig, sizeof(sig))) return 3;
    } else {
      if (signature.size() != 128 + n * 64) return 2;
      sig.ring_size = static_cast<uint16_t>(n);
      memcpy(sig.challenge, signature.data(), 32); memcpy(sig.key_image, signature.data() + 32, 32);
      memcpy(sig.auxiliary_image_1, signature.data() + 64, 32); memcpy(sig.auxiliary_image_2, signature.data() + 96, 32);
      memcpy(sig.responses_g, signature.data() + 128, n * 32);
      memcpy(sig.responses_x, signature.data() + 128 + n * 32, n * 32);
      ok = zano_clsag_ggx_verify(message, ring.data(), n, spend + 96, spend + 128, sig);
    }
    if (ok && signing) {
      append(output, sig.challenge, 32); append(output, sig.key_image, 32);
      append(output, sig.auxiliary_image_1, 32); append(output, sig.auxiliary_image_2, 32);
      append(output, &sig.responses_g[0][0], n * 32); append(output, &sig.responses_x[0][0], n * 32);
    }
    secure_zero(&sig, sizeof(sig));
  }
  secure_zero(input.data(), input.size());
  if (!ok) return 1;
  if (signing && !write_file(argv[3], output)) return 2;
  return 0;
}
