#include <cstdio>
#include <cstring>
#include <initializer_list>
#include "CryptoExtended.h"
#include "KaspaTransaction.h"
#include "XrpTransaction.h"
#include "SensitiveValue.h"
using namespace hexwallet;

#define REQUIRE(c) do { if (!(c)) { printf("signing-audit FAIL line=%d: %s\n", __LINE__, #c); return false; } } while (0)
namespace {
void print_hex(const char *name, const uint8_t *p, size_t size) {
  printf("%s=", name);
  for (size_t i = 0; i < size; ++i) printf("%02x", p[i]);
  puts("");
}
bool erased(const uint8_t *p, size_t n) {
  uint8_t any = 0; for (size_t i = 0; i < n; ++i) any |= p[i]; return any == 0;
}
bool xrp_test(bool bounds_only) {
  uint8_t private_key[32]{}; private_key[31] = 1;
  uint8_t public_key[33], payload[50] = {1};
  REQUIRE(public_key_from_private(private_key, public_key) == WalletError::Ok);
  payload[7] = 0x0f; payload[8] = 0x42; payload[9] = 0x40;
  payload[17] = 10; payload[21] = 1; payload[25] = 100;
  memset(payload + 30, 0x11, 20);
  XrpTransaction tx{};
  REQUIRE(xrp_review_payload(payload, sizeof(payload), public_key, &tx) == XrpError::Ok);
  uint8_t output[kXrpMaxSigned + 1];
  if (bounds_only) {
    tx.review.unsigned_size = UINT16_MAX;
    memset(output, 0xa5, sizeof(output)); size_t size = sizeof(output) - 1;
    REQUIRE(xrp_sign_transaction(tx, private_key, output, &size) != XrpError::Ok);
    REQUIRE(size == 0 && erased(output, sizeof(output) - 1) && output[sizeof(output) - 1] == 0xa5);
    return true;
  }
  REQUIRE(run_xrp_self_tests());
  size_t size = sizeof(output) - 1;
  REQUIRE(xrp_sign_transaction(tx, private_key, output, &size) == XrpError::Ok && size > tx.review.unsigned_size);
  for (unsigned mutation = 0; mutation < 22; ++mutation) {
    XrpTransaction changed = tx;
    switch (mutation) {
      case 0: changed.review.amount_drops++; break;
      case 1: changed.review.fee_drops++; break;
      case 2: changed.review.destination[0] ^= 1; break;
      case 3: changed.review.sequence++; break;
      case 4: changed.review.last_ledger_sequence++; break;
      case 5: changed.review.signature_offset--; break;
      case 6: changed.review.amount_text[0] ^= 1; break;
      case 7: changed.review.fee_text[0] ^= 1; break;
      case 8: changed.review.destination_text[0] ^= 1; break;
      case 9: changed.review.source_text[0] ^= 1; break;
      case 10: changed.review.hash_text[0] ^= 1; break;
      case 11: changed.review.public_key[1] ^= 1; break;
      case 12: changed.review.source[0] ^= 1; break;
      case 13: changed.review.signing_hash[0] ^= 1; break;
      case 14: changed.review.unsigned_tx[0] ^= 1; break;
      case 15: changed.review.unsigned_size = 0; break;
      case 16: changed.review.unsigned_size = kXrpMaxUnsigned + 1; break;
      case 17: changed.review.has_destination_tag = true; break;
      case 18: changed.review.destination_tag = 123; break;
      case 19: changed.review.signature_offset = UINT16_MAX; break;
      case 20: changed.payload[9] ^= 1; break;
      case 21: changed.payload[29] = 1; break; // hidden tag without presence flag
    }
    memset(output, 0xa5, sizeof(output)); size = sizeof(output) - 1;
    const XrpError result = xrp_sign_transaction(changed, private_key, output, &size);
    if (result == XrpError::Ok) printf("XRP accepted mutation=%u\n", mutation);
    REQUIRE(result != XrpError::Ok);
    REQUIRE(size == 0 && erased(output, sizeof(output) - 1) && output[sizeof(output) - 1] == 0xa5);
  }
  // Both tag forms must remain signable.
  for (unsigned tag = 0; tag < 2; ++tag) {
    payload[1] = static_cast<uint8_t>(tag); payload[29] = tag ? 9 : 0;
    REQUIRE(xrp_review_payload(payload, sizeof(payload), public_key, &tx) == XrpError::Ok);
    size = sizeof(output) - 1;
    REQUIRE(xrp_sign_transaction(tx, private_key, output, &size) == XrpError::Ok);
  }
  for (size_t capacity : {size_t(0), size_t(1), size_t(100)}) {
    memset(output, 0xa5, sizeof(output)); size = capacity;
    REQUIRE(xrp_sign_transaction(tx, private_key, output, &size) != XrpError::Ok);
    REQUIRE(size == 0 && erased(output, capacity) && output[capacity] == 0xa5);
  }
  puts("xrp-review-signing-audit=pass mutations=22");
  return true;
}

bool kaspa_test(bool bounds_only) {
  uint8_t seed[64]{};
  SensitiveValue<HdPrivateNode> master;
  REQUIRE(hd_private_from_seed(seed, sizeof(seed), &master.get()) == WalletError::Ok);
  DerivedAddress derived{};
  const auto *network = find_network_profile("kas");
  REQUIRE(network && derive_address(master.get(), nullptr, *network, 0, 0, 0, &derived) == WalletError::Ok);
  uint8_t xonly[32], parity;
  REQUIRE(secp256k1_xonly_public_key(derived.private_key, xonly, &parity) == WalletError::Ok);
  clear_derived_address(&derived);
  KaspaTransaction tx{};
  tx.input_count = tx.output_count = 1;
  tx.inputs[0].value = 2000000;
  tx.inputs[0].sigop_count = 1;
  tx.inputs[0].script_size = 34;
  tx.inputs[0].script[0] = 32;
  memcpy(tx.inputs[0].script + 1, xonly, 32);
  tx.inputs[0].script[33] = 0xac;
  tx.outputs[0].value = 1999000;
  tx.outputs[0].script_size = 34;
  memcpy(tx.outputs[0].script, tx.inputs[0].script, 34);
  REQUIRE(kaspa_review(&tx) == KaspaError::Ok);
  uint8_t output[2049];
  if (bounds_only) {
    uint8_t digest[32], signatures[kKaspaMaxInputs][kKaspaSignatureSize]{};
    for (unsigned mutation = 0; mutation < 5; ++mutation) {
      KaspaTransaction changed = tx;
      if (mutation == 0) changed.input_count = UINT8_MAX;
      if (mutation == 1) changed.output_count = UINT8_MAX;
      if (mutation == 2) changed.payload_size = UINT8_MAX;
      if (mutation == 3) changed.inputs[0].script_size = UINT8_MAX;
      if (mutation == 4) changed.outputs[0].script_size = UINT8_MAX;
      REQUIRE(kaspa_sighash(changed, 0, KaspaSighash::All, digest) != KaspaError::Ok);
      REQUIRE(kaspa_transaction_id(changed, digest) != KaspaError::Ok);
      uint64_t compute, transient, storage;
      REQUIRE(kaspa_masses(changed, &compute, &transient, &storage) != KaspaError::Ok);
      memset(output, 0xa5, sizeof(output)); size_t size = sizeof(output) - 1;
      REQUIRE(kaspa_serialize_transaction(changed, signatures, output, &size) != KaspaError::Ok);
      REQUIRE(size == 0 && erased(output, sizeof(output) - 1) && output[sizeof(output) - 1] == 0xa5);
    }
    return true;
  }
  size_t size = sizeof(output) - 1;
  REQUIRE(kaspa_sign_transaction(tx, master.get(), output, &size) == KaspaError::Ok);
  print_hex("kaspa-signed", output, size);
  print_hex("kaspa-key", xonly, sizeof(xonly));
  REQUIRE(tx.compute_mass == 1624 && tx.transient_mass == 1056 && tx.storage_mass == 250);
  for (unsigned mutation = 0; mutation < 29; ++mutation) {
    KaspaTransaction changed = tx;
    switch (mutation) {
      case 0: changed.fee++; break;
      case 1: changed.input_total++; break;
      case 2: changed.output_total++; break;
      case 3: changed.outputs[0].address[0] ^= 1; break;
      case 4: changed.compute_mass++; break;
      case 5: changed.transient_mass++; break;
      case 6: changed.storage_mass++; break;
      case 7: changed.lock_time++; break;
      case 8: changed.inputs[0].sequence++; break;
      case 9: changed.inputs[0].previous_outpoint.index++; break;
      case 10: changed.inputs[0].previous_outpoint.transaction_id[0]++; break;
      case 11: changed.inputs[0].value++; break;
      case 12: changed.outputs[0].value++; break;
      case 13: changed.outputs[0].script[1] ^= 1; break;
      case 14: changed.inputs[0].sigop_count = 0; break;
      case 15: changed.inputs[0].address_index = 0x80000000u; break;
      case 16: changed.inputs[0].script_size = 255; break;
      case 17: changed.outputs[0].script_size = 255; break;
      case 18: changed.input_count = 255; break;
      case 19: changed.output_count = 255; break;
      case 20: changed.payload_size = 255; break;
      case 21: changed.outputs[0].wallet_owned = true; break;
      case 22: changed.outputs[0].change = true; break;
      case 23: changed.request_hash++; break;
      case 24: changed.inputs[0].account_index++; break;
      case 25: changed.payload_size = 1; changed.payload[0] = 0x42; break;
      case 26: changed.review_hash[0] ^= 1; break;
      case 27: changed.inputs[0].change = 1; break;
      case 28: changed.inputs[0].address_index = 1; break;
    }
    memset(output, 0xa5, sizeof(output)); size = sizeof(output) - 1;
    const auto result = kaspa_sign_transaction(changed, master.get(), output, &size);
    if (result == KaspaError::Ok) printf("Kaspa accepted mutation=%u\n", mutation);
    REQUIRE(result != KaspaError::Ok);
    REQUIRE(size == 0 && erased(output, sizeof(output) - 1) && output[sizeof(output) - 1] == 0xa5);
  }
  for (size_t capacity : {size_t(0), size_t(1), size_t(100)}) {
    memset(output, 0xa5, sizeof(output)); size = capacity;
    REQUIRE(kaspa_sign_transaction(tx, master.get(), output, &size) != KaspaError::Ok);
    REQUIRE(size == 0 && erased(output, capacity) && output[capacity] == 0xa5);
  }
  REQUIRE(run_kaspa_self_tests());
  puts("kaspa-review-signing-audit=pass mutations=29");
  return true;
}

bool kaspa_reference() {
  for (unsigned variant = 0; variant < 4; ++variant) {
    KaspaTransaction tx{};
    tx.input_count = variant == 2 ? kKaspaMaxInputs : (variant == 1 ? 2 : 1);
    tx.output_count = variant == 2 ? kKaspaMaxOutputs : (variant == 1 ? 2 : 1);
    tx.lock_time = variant ? UINT64_C(1615462089000) : 0;
    if (variant == 3) { tx.payload_size = 3; memcpy(tx.payload, "KAS", 3); }
    uint8_t signatures[kKaspaMaxInputs][kKaspaSignatureSize]{};
    for (size_t i = 0; i < tx.input_count; ++i) {
      auto &input = tx.inputs[i];
      memset(input.previous_outpoint.transaction_id, static_cast<int>(i + 1), 32);
      input.previous_outpoint.index = static_cast<uint32_t>(i + 7);
      input.sequence = variant ? UINT64_MAX - i : 0;
      input.sigop_count = 1;
      input.value = 100000000;
      input.script_size = 34;
      input.script[0] = 32; memset(input.script + 1, 0x11, 32); input.script[33] = 0xac;
      memset(signatures[i], static_cast<int>(0x11 + i), 64); signatures[i][64] = 1;
    }
    for (size_t i = 0; i < tx.output_count; ++i) {
      auto &output = tx.outputs[i];
      output.value = 100000;
      output.script_size = 34;
      output.script[0] = 32; memset(output.script + 1, static_cast<int>(0x21 + i), 32); output.script[33] = 0xac;
    }
    REQUIRE(kaspa_masses(tx, &tx.compute_mass, &tx.transient_mass, &tx.storage_mass) == KaspaError::Ok);
    printf("case=%u\nmasses=%llu,%llu,%llu\n", variant,
           static_cast<unsigned long long>(tx.compute_mass), static_cast<unsigned long long>(tx.transient_mass),
           static_cast<unsigned long long>(tx.storage_mass));
    uint8_t wire[4097]; size_t size = sizeof(wire) - 1;
    REQUIRE(kaspa_serialize_transaction(tx, signatures, wire, &size) == KaspaError::Ok);
    print_hex("wire", wire, size);
    uint8_t digest[32];
    REQUIRE(kaspa_transaction_id(tx, digest) == KaspaError::Ok);
    print_hex("id", digest, sizeof(digest));
    for (size_t i = 0; i < tx.input_count; ++i) {
      for (const auto hash : {KaspaSighash::All, KaspaSighash::None, KaspaSighash::Single,
                             KaspaSighash::AllAnyoneCanPay, KaspaSighash::NoneAnyoneCanPay, KaspaSighash::SingleAnyoneCanPay}) {
        REQUIRE(kaspa_sighash(tx, i, hash, digest) == KaspaError::Ok);
        print_hex("sighash", digest, sizeof(digest));
      }
    }
    // Every short output buffer is erased, including failures after partial writes.
    for (size_t capacity = 0; capacity < size; ++capacity) {
      memset(wire, 0xa5, sizeof(wire)); size_t short_size = capacity;
      REQUIRE(kaspa_serialize_transaction(tx, signatures, wire, &short_size) != KaspaError::Ok);
      REQUIRE(short_size == 0 && erased(wire, capacity) && wire[capacity] == 0xa5);
    }
  }
  return true;
}
}  // namespace

int signing_audit(const char *test) {
  if (!strcmp(test, "kaspa-reference")) return kaspa_reference() ? 0 : 1;
  if (!strcmp(test, "xrp-bounds")) return xrp_test(true) ? 0 : 1;
  if (!strcmp(test, "xrp")) return xrp_test(false) ? 0 : 1;
  if (!strcmp(test, "kaspa-bounds")) return kaspa_test(true) ? 0 : 1;
  if (!strcmp(test, "kaspa")) return kaspa_test(false) ? 0 : 1;
  if (!strcmp(test, "all")) return xrp_test(false) && xrp_test(true) && kaspa_test(false) && kaspa_test(true) ? 0 : 1;
  return 2;
}
