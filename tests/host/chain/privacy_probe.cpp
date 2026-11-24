// Test-only binary bridge. Never linked into the firmware command dispatcher.
#include <cstdio>
#include <cstring>
#include <vector>
#include "RyoMlsag.h"
#include "RyoBulletproof.h"
#include "RyoTransaction.h"
#include "RyoPhonePayment.h"
#include "ZanoClsag.h"
#include "ZanoOutput.h"
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
uint64_t le64(const uint8_t *p) {
  return uint64_t(le32(p)) | (uint64_t(le32(p + 4)) << 32);
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
  if (argc == 2 && !strcmp(argv[1], "privacy-ryo-phone-bounds")) {
    RyoPhonePayment state{};
    uint8_t key[32] = {1};
    for (const size_t size : {kRyoPhonePayloadMax - 1, kRyoPhonePayloadMax, kRyoPhonePayloadMax + 1}) {
      for (const size_t wire : {sizeof(state.wire) - 1, sizeof(state.wire), sizeof(state.wire) + 1}) {
        std::vector<uint8_t> payload(size, 0xff); // invalid wire version after the guarded copy
        payload[0] = 1;
        payload[1] = static_cast<uint8_t>(wire);
        payload[2] = static_cast<uint8_t>(wire >> 8);
        memset(state.wire, 0, sizeof(state.wire));
        if (ryo_phone_prepare(payload.data(), size, key, key, state)) return 1;
        const size_t copied = size <= kRyoPhonePayloadMax && wire <= sizeof(state.wire) ? wire : 0;
        for (size_t i = 0; i < sizeof(state.wire); ++i)
          if (state.wire[i] != (i < copied ? 0xff : 0)) return 1;
      }
    }
    printf("Ryo payload=%zu wire=%zu, 9 copy boundaries passed\n", kRyoPhonePayloadMax, sizeof(state.wire));
    return 0;
  }
  if (argc == 4 && !strcmp(argv[1], "privacy-ryo-spend")) {
    std::vector<uint8_t> wire, data;
    if (!read_file(argv[2], wire) || !read_file(argv[3], data) || data.size() < 161) return 2;
    RyoTransactionView tx{};
    if (ryo_parse_transaction(wire.data(), wire.size(), &tx) != RyoTxError::Ok) return 1;
    const size_t stride = 140 + tx.ring_size * 72;
    if (data.size() != 161 + tx.input_count * stride) return 2;
    const uint8_t *p = data.data();
    RyoPublicAddress recipient;
    memcpy(recipient.spend, p + 96, 32);
    memcpy(recipient.view, p + 128, 32);
    std::vector<RyoSpendSource> sources(tx.input_count);
    std::vector<RyoRingMember> rings(tx.input_count * tx.ring_size);
    std::vector<uint64_t> offsets(rings.size());
    for (size_t i = 0; i < sources.size(); ++i) {
      auto &s = sources[i];
      const uint8_t *q = p + 161 + i * stride;
      s.real_index = le32(q);
      s.funding_output_index = le64(q + 4);
      memcpy(s.funding_tx_public, q + 12, 32);
      memcpy(s.funding_ecdh, q + 44, 64);
      memcpy(s.pseudo_mask, q + 108, 32);
      s.ring_size = tx.ring_size;
      size_t start = i * s.ring_size;
      s.absolute_offsets = &offsets[start];
      s.ring = &rings[start];
      for (size_t j = 0; j < s.ring_size; ++j) {
        const uint8_t *m = q + 140 + 72 * j;
        offsets[start + j] = le64(m);
        memcpy(rings[start + j].destination, m + 8, 32);
        memcpy(rings[start + j].commitment, m + 40, 32);
      }
    }
    RyoSpendReview reviewed{};
    if (!ryo_review_spend(wire.data(), wire.size(), sources.data(), sources.size(), p, p + 32, p + 64, recipient, &reviewed))
      return 1;
    if (p[160] == 1) ++reviewed.payment.fee;
    if (p[160] == 2) reviewed.binding[0] ^= 1;
    if (p[160] == 3) reviewed.payment.payment_id[31] ^= 1;
    std::vector<uint8_t> signed_tx(wire.size(), 0xa5);
    RyoMlsagSignature workspace{};
    size_t size = signed_tx.size();
    const uint8_t entropy[32] = {42}; // public reproducible fixture
    if (!ryo_sign_spend(wire.data(), wire.size(), sources.data(), sources.size(), p, p + 32, p + 64, recipient,
                        reviewed, entropy, &workspace, signed_tx.data(), &size))
      return !size && erased(signed_tx.data(), signed_tx.size()) ? 1 : 3;
    if (size != wire.size() || !erased(&workspace, sizeof(workspace))) return 3;
    for (size_t i = 0; i < sources.size(); ++i)
      if (ryo_transaction_verify_input(signed_tx.data(), size, i, sources[i].ring, tx.ring_size) != RyoTxError::Ok) return 3;
    printf("total=%llu\namount=%llu\nchange=%llu\nfee=%llu\n", (unsigned long long)reviewed.total_input,
           (unsigned long long)reviewed.payment.amount, (unsigned long long)reviewed.payment.change,
           (unsigned long long)reviewed.payment.fee);
    print_hex("signed", signed_tx.data(), size);
    return 0;
  }
  if (argc == 4 && !strcmp(argv[1], "privacy-ryo-payment")) {
    std::vector<uint8_t> wire, keys;
    RyoPublicAddress recipient, wallet;
    if (!read_file(argv[2], wire) || !read_file(argv[3], keys) || keys.size() != 160) return 2;
    memcpy(&recipient, keys.data() + 32, 64);
    memcpy(&wallet, keys.data() + 96, 64);
    RyoPaymentDetails result;
    memset(&result, 0xa5, sizeof(result));
    if (!ryo_decode_payment(wire.data(), wire.size(), keys.data(), recipient, wallet, &result))
      return result.amount || result.change || result.fee || result.has_payment_id || !erased(result.payment_id, 32) ? 3 : 1;
    printf("amount=%llu\nchange=%llu\nfee=%llu\n", (unsigned long long)result.amount,
           (unsigned long long)result.change, (unsigned long long)result.fee);
    if (result.has_payment_id) print_hex("payment_id", result.payment_id, 32);
    return 0;
  }
  if (argc == 3 && !strcmp(argv[1], "privacy-zano-output")) {
    std::vector<uint8_t> data;
    if (!read_file(argv[2], data) || data.size() != 153 || data[152] > 1) return 2;
    ZanoConfidentialOutput out;
    memset(&out, 0xa5, sizeof(out));
    if (!zano_build_output(data.data(), le64(data.data() + 128), data.data() + 32, data.data() + 64, data.data() + 96,
                           le64(data.data() + 136), le64(data.data() + 144), data[152] != 0, &out)) return erased(&out, sizeof(out)) ? 1 : 3;
    print_hex("stealth", out.stealth_address, 32);
    print_hex("concealing", out.concealing_point, 32);
    print_hex("commitment", out.amount_commitment, 32);
    print_hex("asset", out.blinded_asset, 32);
    printf("amount=%llu\npayment_id=%llu\n", (unsigned long long)out.encrypted_amount,
           (unsigned long long)out.encrypted_payment_id);
    return 0;
  }
  if (argc == 3 && !strcmp(argv[1], "privacy-zano-scan")) {
    std::vector<uint8_t> data;
    if (!read_file(argv[2], data) || data.size() != 248) return 2;
    const auto *p = data.data();
    ZanoConfidentialOutput output{};
    memcpy(output.stealth_address, p + 104, 32);
    memcpy(output.concealing_point, p + 136, 32);
    memcpy(output.amount_commitment, p + 168, 32);
    memcpy(output.blinded_asset, p + 200, 32);
    output.encrypted_amount = le64(p + 232);
    output.encrypted_payment_id = le64(p + 240);
    ZanoReceivedOutput received;
    memset(&received, 0xa5, sizeof(received));
    if (!zano_scan_output(p, p + 32, p + 64, le64(p + 96), output, &received))
      return erased(&received, sizeof(received)) ? 1 : 3;
    print_hex("asset", received.asset_id, 32);
    print_hex("amount_mask", received.amount_mask, 32);
    print_hex("asset_mask", received.asset_mask, 32);
    printf("amount=%llu\npayment_id=%llu\n", (unsigned long long)received.amount, (unsigned long long)received.payment_id);
    return 0;
  }
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
