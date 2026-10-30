#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ChainCommon.h"
#include "ChainTransaction.h"
#include "CosmosTransaction.h"
#include "WalletAltAddresses.h"
#include "WalletEngine.h"
#include "PolkadotTransaction.h"
#include "BlsG2.h"
#include "WalletNetworks.h"
#include "ZcashTransaction.h"
#include "DashTransaction.h"
#include "EvmTransaction.h"
#include "QrlXmss.h"
using namespace hexwallet;
static void hex(const char *key, const uint8_t *p, size_t n) {
  printf("%s=", key); for (size_t i = 0; i < n; ++i) printf("%02x", p[i]); puts("");
}
int main(int argc, char **argv) {
  if (argc == 2 && !strcmp(argv[1], "dash-sign-selftest")) {
    const bool ok = run_dash_self_tests() && run_dash_signature_self_test();
    printf("dash-sign=%s\n", ok ? "pass" : "FAIL");
    return ok ? 0 : 1;
  }
  // EVM signing needs the real keccak/secp256k1 stack, so the stubbed host
  // harness cannot run it; this probe does.
  if (argc == 2 && !strcmp(argv[1], "evm-sign-selftest")) {
    const bool ok = run_evm_transaction_self_test();
    printf("evm-sign=%s\n", ok ? "pass" : "FAIL");
    return ok ? 0 : 1;
  }
  if (argc == 2 && !strcmp(argv[1], "chain-selftest")) {
    const bool ok = run_chain_self_tests();
    if (!ok) report_chain_self_tests();
    printf("chain=%s\n", ok ? "pass" : "FAIL");
    return ok ? 0 : 1;
  }
  // Full Zcash signing path with the real BIP32/ECDSA stack. The main host
  // suite stubs derivation on purpose, so this probe is where the device-only
  // signer (including t3 P2SH spends) is executed on the host.
  if (argc == 2 && !strcmp(argv[1], "zcash-sign-selftest")) {
    const bool sighash = run_zcash_sighash_self_tests();
    const bool transaction = run_zcash_transaction_self_test();
    printf("zcash-sighash=%s\nzcash-transaction=%s\n",
           sighash ? "pass" : "FAIL", transaction ? "pass" : "FAIL");
    return (sighash && transaction) ? 0 : 1;
  }
  // Cosmos TxRaw byte comparison, which needs the real curve.
  if (argc == 2 && !strcmp(argv[1], "cosmos-sign-selftest")) {
    const bool review = run_cosmos_self_tests();
    const bool signature = run_cosmos_signature_self_test();
    printf("cosmos-review=%s\ncosmos-signature=%s\n",
           review ? "pass" : "FAIL", signature ? "pass" : "FAIL");
    return (review && signature) ? 0 : 1;
  }
  if (argc != 5 && argc != 6) return 2;
  if (!strcmp(argv[1], "chain-selftest")) {
    const bool ok = run_chain_self_tests();
    if (!ok) report_chain_self_tests();
    printf("chain=%s\n", ok ? "pass" : "FAIL");
    return ok ? 0 : 1;
  }
  if (!strcmp(argv[1], "qrl-vector") || !strcmp(argv[1], "qrl-mapped-vector")) {
    uint8_t test_seed[kQrlSeedSize]{}, public_key[kQrlPublicKeySize];
    size_t n = 0;
    if (!strcmp(argv[1], "qrl-mapped-vector")) {
      uint8_t bip39_test_seed[kSeedSize]{};
      if (!chain_parse_hex(argv[2], bip39_test_seed, sizeof(bip39_test_seed), &n) || n != sizeof(bip39_test_seed)) return 2;
      const auto mapped = qrl_seed_from_bip39(bip39_test_seed,
          static_cast<uint32_t>(strtoul(argv[3], nullptr, 10)), test_seed);
      secure_zero(bip39_test_seed, sizeof(bip39_test_seed));
      if (mapped != WalletError::Ok) return 1;
    } else if (!chain_parse_hex(argv[2], test_seed, sizeof(test_seed), &n) || n != sizeof(test_seed)) return 2;
    const unsigned height = static_cast<unsigned>(strtoul(argv[4], nullptr, 10));
    if (height > 255) return 2;
    memset(public_key, 0xa5, sizeof(public_key));
    auto cancel = [](uint32_t, uint32_t, void *) { return false; };
    const auto result = qrl_xmss_public_key_ex(test_seed, static_cast<uint8_t>(height),
        argc == 6 ? static_cast<QrlProgressHook>(cancel) : nullptr, nullptr, public_key);
    bool zero = true; for (auto b : public_key) zero &= b == 0;
    printf("error=%u\nzero=%u\n", static_cast<unsigned>(result), zero);
    secure_zero(test_seed, sizeof(test_seed));
    if (result != WalletError::Ok) return 1;
    char address[kQrlAddressTextSize]{};
    if (qrl_address_from_public_key(public_key, address, sizeof(address)) != WalletError::Ok) return 1;
    hex("public", public_key, sizeof(public_key)); printf("address=%s\n", address);
    return 0;
  }
  if (!strcmp(argv[1], "bls")) {
    const bool ok = run_bls_g2_self_tests();
    printf("bls=%s\n", ok ? "pass" : "FAIL");
    return ok ? 0 : 1;
  }
  uint8_t seed[64] = {}, payload[kChainMaxPayload] = {};
  size_t seed_size = 0, payload_size = 0;
  if (!chain_parse_hex(argv[2], seed, sizeof(seed), &seed_size) || seed_size != 64 ||
      !chain_parse_hex(argv[3], payload, sizeof(payload), &payload_size)) return 2;
  const uint32_t index = static_cast<uint32_t>(strtoul(argv[4], nullptr, 10));
  HdPrivateNode master = {}; DerivedAddress address = {};
  const NetworkProfile *network = find_network_profile(argv[1]);
  if (!network || hd_private_from_seed(seed, 64, &master) != WalletError::Ok ||
      derive_address(master, seed, *network, 0, 0, index, &address) != WalletError::Ok) {
    puts("error=derive"); return 1;
  }
  printf("address=%s\npath=%s\n", address.address, address.path);
  clear_derived_address(&address);

  if (network->encoding == AddressEncoding::Evm) {
    EvmSigningRequest tx = {};
    EvmTransactionError error = evm_parse_transaction(payload, payload_size, *network, master, index, &tx);
    printf("error=%u\n", static_cast<unsigned>(error));
    if (error != EvmTransactionError::Ok) return 1;
    printf("sender=%s\nrecipient=%s\namount=%s\nfee=%s\n", tx.from_address,
           tx.recipient_address, tx.amount_text, tx.maximum_fee_text);
    printf("asset=%s\nfee_asset=%s\n", tx.token ? tx.token->symbol : network->symbol,
           network->symbol);
    char review_details[kEvmReviewTextSize];
    if (!evm_review_details(tx, review_details, sizeof(review_details))) return 1;
    const size_t review_length = strlen(review_details);
    // Exact fit must succeed; one byte less must fail without leaking a
    // truncated review or overwriting the caller's guard byte.
    char review_boundary[kEvmReviewTextSize];
    memset(review_boundary, 0xa5, sizeof(review_boundary));
    if (evm_review_details(tx, review_boundary, review_length)) return 1;
    for (size_t i = 0; i < review_length; ++i) if (review_boundary[i] != 0) return 1;
    if (static_cast<unsigned char>(review_boundary[review_length]) != 0xa5) return 1;
    if (!evm_review_details(tx, review_boundary, review_length + 1) ||
        strcmp(review_details, review_boundary)) return 1;
    printf("BEGIN EVM DETAILS\n%sEND EVM DETAILS\n", review_details);
    char access_details[kEvmAccessListTextSize];
    if (!evm_access_list_details(tx, access_details, sizeof(access_details))) return 1;
    if (tx.access_list_addresses != 0) {
      char tiny[9]; memset(tiny, 0xa5, sizeof(tiny));
      if (evm_access_list_details(tx, tiny, 8)) return 1;
      for (size_t i = 0; i < 8; ++i) if (tiny[i] != 0) return 1;
      if (static_cast<unsigned char>(tiny[8]) != 0xa5) return 1;
    }
    printf("access_addresses=%u\naccess_keys=%u\n%s", tx.access_list_addresses,
           tx.access_list_keys, access_details);
    hex("hash", tx.signing_hash, 32);
    uint8_t output[kEvmMaxSignedTransactionSize]; memset(output, 0xa5, sizeof(output));
    size_t capacity = sizeof(output);
    if (argc == 6) {
      if (!strcmp(argv[5], "review")) tx.amount_text[0] ^= 1;
      else if (!strcmp(argv[5], "hash")) tx.signing_hash[0] ^= 1;
      else if (!strcmp(argv[5], "payload")) tx.unsigned_transaction[tx.unsigned_transaction_size - 1] ^= 1;
      else if (!strcmp(argv[5], "index")) ++tx.address_index;
      else if (!strcmp(argv[5], "access-count")) ++tx.access_list_keys;
      else if (!strcmp(argv[5], "access-bytes")) tx.access_list[0] ^= 1;
      else if (!strcmp(argv[5], "type")) tx.type = static_cast<EvmTransactionType>(255);
      else if (!strcmp(argv[5], "call-owner")) tx.call.secondary[0] ^= 1;
      else if (!strcmp(argv[5], "call-flags")) tx.call.has_min_amount = !tx.call.has_min_amount;
      else if (!strcmp(argv[5], "nonce")) ++tx.nonce;
      else if (!strcmp(argv[5], "unterminated-review")) memset(tx.amount_text, '1', sizeof(tx.amount_text));
      else capacity = static_cast<size_t>(strtoul(argv[5], nullptr, 10));
    }
    if (capacity > sizeof(output)) return 2;
    const size_t original = capacity;
    error = evm_sign_transaction(tx, master, output, &capacity);
    printf("sign_error=%u\nsize=%zu\n", static_cast<unsigned>(error), capacity);
    bool zero = true, guard = true;
    for (size_t i = 0; i < original; ++i) zero &= output[i] == 0;
    for (size_t i = original; i < sizeof(output); ++i) guard &= output[i] == 0xa5;
    printf("zero=%u\nguard=%u\n", zero, guard);
    if (error == EvmTransactionError::Ok) hex("signed", output, capacity);
    secure_zero(seed, sizeof(seed)); secure_zero(&master, sizeof(master)); clear_evm_request(&tx);
    return error == EvmTransactionError::Ok ? 0 : 1;
  }

  const NetworkProfile *zcash_network = find_network_profile(argv[1]);
  if (zcash_network != nullptr &&
      zcash_network->encoding == AddressEncoding::ZcashTransparent) {
    if (!payload_size) return 0;
    const ZcashNetworkPolicy *zcash_policy =
        find_zcash_network_policy(zcash_network->id);
    if (zcash_policy == nullptr) return 1;
    const ZcashChainParams chain = {
        zcash_network->id, zcash_network->alt_p2pkh_version,
        zcash_network->alt_p2sh_version, zcash_policy->branch_id,
        zcash_network->derivation_coin_type};
    ZcashSigningRequest request = {};
    ZcashError error = zcash_parse_review_payload(payload, payload_size, chain,
                                                  &request);
    printf("error=%u\n", static_cast<unsigned>(error));
    if (error != ZcashError::Ok) return 1;
    printf("fee=%llu\ninput_total=%llu\noutput_total=%llu\n",
           static_cast<unsigned long long>(request.fee),
           static_cast<unsigned long long>(request.input_total),
           static_cast<unsigned long long>(request.output_total));
    printf("recipient=%s\n", request.outputs[0].address);
    for (size_t index = 0; index < request.input_count; ++index) {
      const ZcashInput &input = request.inputs[index];
      if (input.redeem_size == 0) continue;
      char p2sh_address[kAddressTextSize] = {};
      const bool named =
          address_zcash_transparent_from_script(
              chain.p2pkh_version, chain.p2sh_version, input.script,
              input.script_size, p2sh_address, sizeof(p2sh_address)) ==
          WalletError::Ok;
      printf("p2sh_input=%zu zats=%llu redeem_size=%u address=%s\n", index,
             static_cast<unsigned long long>(input.value),
             static_cast<unsigned>(input.redeem_size),
             named ? p2sh_address : "?");
      hex("redeem", input.redeem, input.redeem_size);
    }
    hex("request_hash", request.request_hash, 32);
    uint8_t output[kZcashMaxTransactionSize] = {};
    size_t output_size = sizeof(output);
    error = zcash_sign_request(request, master, output, &output_size);
    printf("sign_error=%u\nsize=%zu\n", static_cast<unsigned>(error),
           output_size);
    if (error == ZcashError::Ok) {
      hex("signed", output, output_size);
      uint8_t digest[32] = {};
      const ZcashInput &input = request.inputs[0];
      // t3 spends commit the redeem script; P2PKH commits the prevout script.
      const uint8_t *script_code =
          input.redeem_size != 0 ? input.redeem : input.script;
      const size_t script_code_size =
          input.redeem_size != 0 ? input.redeem_size : input.script_size;
      if (zcash_zip243_sighash_v4(output, output_size, script_code,
                                  script_code_size, 0, 0x01, input.value,
                                  chain.branch_id, digest) == ZcashError::Ok) {
        hex("digest", digest, 32);
      }
    }
    secure_zero(&master, sizeof(master));
    return error == ZcashError::Ok ? 0 : 1;
  }

  ChainFamily family = ChainFamily::None;
  if (!chain_family_for_network(argv[1], &family)) { puts("error=unsupported"); return 1; }
  ChainTransaction tx = {};
  ChainError error = chain_review_transaction(family, payload, payload_size, master, seed, index, &tx);
  printf("error=%u\n", static_cast<unsigned>(error));
  if (error != ChainError::Ok) return 1;
  printf("sender=%s\nrecipient=%s\namount=%s\nfee=%s\n", tx.review.sender,
         tx.review.recipient, tx.review.amount, tx.review.fee);
  hex("hash", tx.digest, 32);
  uint8_t output[kChainMaxPayload + 512]; memset(output, 0xa5, sizeof(output));
  size_t capacity = sizeof(output);
  if (argc == 6) {
    if (!strcmp(argv[5], "review")) tx.review.amount[0] ^= 1;
    else if (!strcmp(argv[5], "hash")) tx.digest[0] ^= 1;
    else if (!strcmp(argv[5], "payload")) tx.payload[tx.payload_size - 1] ^= 1;
    else if (!strcmp(argv[5], "index")) ++tx.address_index;
    else capacity = static_cast<size_t>(strtoul(argv[5], nullptr, 10));
  }
  if (capacity > sizeof(output)) return 2;
  const size_t original = capacity;
  error = chain_sign_transaction(tx, master, seed, output, &capacity);
  printf("sign_error=%u\nsize=%zu\n", static_cast<unsigned>(error), capacity);
  bool zero = true, guard = true;
  for (size_t i = 0; i < original; ++i) zero &= output[i] == 0;
  for (size_t i = original; i < sizeof(output); ++i) guard &= output[i] == 0xa5;
  printf("zero=%u\nguard=%u\n", zero, guard);
  if (error == ChainError::Ok) hex("signed", output, capacity);
  secure_zero(seed, sizeof(seed)); secure_zero(&master, sizeof(master));
  return error == ChainError::Ok ? 0 : 1;
}
