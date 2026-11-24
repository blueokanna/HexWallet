#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "base58.h"
#include "AlephiumTransaction.h"
#include "AeternityTransaction.h"
#include "ChainCommon.h"
#include "EvmTransaction.h"
#include "SensitiveValue.h"
#include "WalletCustody.h"
#include "WalletCustomTokens.h"
#include "WalletSession.h"
#include "WalletLink.h"
#include "WalletLinkCrypto.h"
#include "WalletSigning.h"

using namespace hexwallet;

#define CHECK(condition)                                                      \
  do                                                                          \
  {                                                                           \
    if (!(condition))                                                         \
    {                                                                         \
      printf("security-regression FAIL line=%d: %s\n", __LINE__, #condition); \
      return false;                                                           \
    }                                                                         \
  } while (0)

namespace
{

  bool codecs()
  {
    uint8_t bytes[128] = {}, decoded[128] = {};
    char encoded[200] = {};
    for (size_t length = 0; length <= sizeof(bytes); ++length)
    {
      for (size_t i = 0; i < length; ++i)
        bytes[i] = static_cast<uint8_t>(i * 37);
      size_t text_size = sizeof(encoded), decoded_size = sizeof(decoded);
      CHECK(b58enc(encoded, &text_size, bytes, length));
      CHECK(b58dec(decoded, &decoded_size, encoded, text_size - 1));
      CHECK(decoded_size == length && memcmp(bytes, decoded, length) == 0);
    }
    const char nul_in_address[] = {'2', '\0', '3'};
    for (size_t length = 2; length <= sizeof(nul_in_address); ++length)
    {
      size_t size = sizeof(decoded);
      memset(decoded, 0xa5, sizeof(decoded));
      CHECK(!b58dec(decoded, &size, nul_in_address, length));
      CHECK(decoded[0] == 0xa5 && decoded[sizeof(decoded) - 1] == 0xa5);
    }
    size_t capacity = sizeof(encoded);
    CHECK(!b58enc(encoded, &capacity, bytes, SIZE_MAX));
    CHECK(!ripple_b58enc(encoded, &capacity, bytes, SIZE_MAX));

    // Lengths that used to wrap to small values must fail before reading input.
    uint8_t output[16];
    memset(output, 0xa5, sizeof(output));
    RlpWriter raw(output, sizeof(output));
    CHECK(raw.raw(bytes, 1) && !raw.raw(bytes, SIZE_MAX) && !raw.ok());
    CHECK(raw.size() == 1 && output[1] == 0xa5);
    RlpWriter item(output, sizeof(output));
    CHECK(!item.bytes(bytes, SIZE_MAX) && item.size() == 0 && !item.ok());
    RlpWriter null_writer(nullptr, 16);
    CHECK(!null_writer.ok() && !null_writer.bytes(bytes, 1));
    RlpWriter zero(output, sizeof(output));
    CHECK(zero.integer(nullptr, 0) && zero.size() == 1 && output[0] == 0x80);
    size_t size = 99;
    CHECK(!rlp_wrap_list(bytes, SIZE_MAX, output, sizeof(output), &size) && size == 0);
    CHECK(rlp_wrap_list(nullptr, 0, output, sizeof(output), &size) && size == 1 && output[0] == 0xc0);
    CHECK(chain_hex_length(SIZE_MAX) == 0 && chain_hex_length(SIZE_MAX / 2 + 1) == 0);
    CHECK(chain_hex_length(0) == 1 && chain_hex_length(32) == 65);
    chain_hex(bytes, SIZE_MAX / 2 + 1, encoded, sizeof(encoded));
    CHECK(encoded[0] == '\0');

    // Exact-size and one-byte-short RLP buffers exercise both prefix encodings.
    for (size_t length = 0; length <= 64; ++length)
    {
      const size_t needed = length + (length <= 55 ? 1 : 2);
      uint8_t wire[67];
      memset(wire, 0xa5, sizeof(wire));
      CHECK(rlp_wrap_list(bytes, length, wire, needed, &size) && size == needed);
      CHECK(wire[needed] == 0xa5);
      CHECK(!rlp_wrap_list(bytes, length, wire, needed - 1, &size) && size == 0);
    }
    // Compact integer widths 1, 2 and 4 all precede the fee-policy rejection.
    // The old decoder formed out + 33 before subtracting the width.
    const uint8_t compact_cases[][9] = {
        {0, 0, 0, 1, 1, 1},
        {0, 0, 0, 0x40, 0x40, 1, 1},
        {0, 0, 0, 0x80, 0, 0x40, 0, 1, 1}};
    const size_t compact_sizes[] = {6, 7, 9};
    const uint8_t public_key[33] = {};
    for (size_t i = 0; i < 3; ++i) {
      ChainReview review{};
      uint8_t digest[32];
      CHECK(alephium_review(compact_cases[i], compact_sizes[i], public_key,
                           "test", review, digest) == ChainError::FeePolicy);
    }
    puts("security-codecs=pass");
    return true;
  }

  bool evm_registry_binding()
  {
    const auto *network = find_network_profile("eth");
    CHECK(network != nullptr && custom_token_count() == 0);
    const uint8_t seed[32] = {}; // Public test wallet, never a real key.
    SensitiveValue<HdPrivateNode> master;
    CHECK(hd_private_from_seed(seed, sizeof(seed), &master.get()) == WalletError::Ok);
    uint8_t contract[20], recipient[20], calldata[68], fields[256], wire[272];
    memset(contract, 0x44, sizeof(contract));
    memset(recipient, 0x55, sizeof(recipient));
    CHECK(custom_token_add("eth", contract, sizeof(contract), "UNIT", "Unit token", 6) == CustomTokenError::Ok);
    CHECK(token_build_erc20_transfer(recipient, 1000000, calldata, sizeof(calldata)));
    RlpWriter writer(fields, sizeof(fields));
    const uint8_t one = 1, gas[] = {0xfd, 0xe8};
    CHECK(writer.integer(nullptr, 0) && writer.bytes(&one, 1) && writer.bytes(gas, sizeof(gas)) &&
          writer.bytes(contract, sizeof(contract)) && writer.integer(nullptr, 0) &&
          writer.bytes(calldata, sizeof(calldata)) && writer.bytes(&one, 1) &&
          writer.integer(nullptr, 0) && writer.integer(nullptr, 0));
    size_t wire_size = 0;
    CHECK(rlp_wrap_list(fields, writer.size(), wire, sizeof(wire), &wire_size));
    EvmSigningRequest reviewed{};
    CHECK(evm_parse_for_review(wire, wire_size, *network, master.get(), 0, &reviewed) == EvmTransactionError::Ok);
    CHECK(reviewed.has_call && !reviewed.opaque && strcmp(reviewed.amount_text, "1") == 0);
    uint8_t *abi = nullptr;
    for (size_t i = 0; i + sizeof(calldata) <= wire_size; ++i)
      if (!memcmp(wire + i, calldata, sizeof(calldata))) abi = wire + i;
    CHECK(abi);
    abi[4] = 1; // Nonzero high address byte on a registered ERC-20 transfer.
    EvmSigningRequest invalid{};
    CHECK(evm_parse_for_review(wire, wire_size, *network, master.get(), 0, &invalid) != EvmTransactionError::Ok);
    abi[4] = 0;
    uint8_t signed_wire[kEvmMaxSignedTransactionSize + 1];
    size_t signed_size = sizeof(signed_wire) - 1;
    CHECK(evm_sign_transaction(reviewed, master.get(), signed_wire, &signed_size) == EvmTransactionError::Ok);

    // Same contract, units and table slot; only the displayed identity changes.
    CHECK(custom_token_add("eth", contract, sizeof(contract), "OTHER", "Other token", 6) == CustomTokenError::Ok);
    memset(signed_wire, 0xa5, sizeof(signed_wire));
    signed_size = sizeof(signed_wire) - 1;
    CHECK(evm_sign_transaction(reviewed, master.get(), signed_wire, &signed_size) == EvmTransactionError::WrongWallet);
    CHECK(signed_size == 0 && signed_wire[sizeof(signed_wire) - 1] == 0xa5);
    for (size_t i = 0; i < sizeof(signed_wire) - 1; ++i)
      CHECK(signed_wire[i] == 0);
    // A fresh review of the new declaration remains usable.
    CHECK(evm_parse_for_review(wire, wire_size, *network, master.get(), 0, &reviewed) == EvmTransactionError::Ok);
    signed_size = sizeof(signed_wire) - 1;
    CHECK(evm_sign_transaction(reviewed, master.get(), signed_wire, &signed_size) == EvmTransactionError::Ok);

    char details[kEvmReviewTextSize], amount[96];
    CHECK(evm_review_details(reviewed, details, sizeof(details)));
    CHECK(strstr(details, "UNVERIFIED CUSTOM TOKEN") != nullptr);
    CHECK(evm_review_amount(reviewed, "OTHER", amount, sizeof(amount)));
    char tiny[2] = {'x', 'x'};
    CHECK(!evm_review_amount(reviewed, "OTHER", tiny, sizeof(tiny)) && tiny[0] == '\0');
    memset(reviewed.amount_text, '9', sizeof(reviewed.amount_text));
    CHECK(!evm_review_details(reviewed, details, sizeof(details)) && details[0] == '\0');
    CHECK(!evm_review_amount(reviewed, "OTHER", amount, sizeof(amount)) && amount[0] == '\0');
    CHECK(evm_parse_for_review(wire, wire_size, *network, master.get(), 0, &reviewed) == EvmTransactionError::Ok);
    memset(reviewed.token_id_text, '9', sizeof(reviewed.token_id_text));
    CHECK(!evm_review_details(reviewed, details, sizeof(details)) && details[0] == '\0');
    CHECK(!evm_review_amount(reviewed, "OTHER", amount, sizeof(amount)) && amount[0] == '\0');
    CHECK(custom_token_remove("eth", contract, sizeof(contract)) == CustomTokenError::Ok);
    puts("security-evm-review=pass");
    return true;
  }
}

bool run_security_regressions()
{
  CHECK(run_link_crypto_self_test());
  const char *words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  uint8_t actual[kSeedSize], expected[kSeedSize];
  size_t expected_size;
  CHECK(chain_parse_hex("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
                        "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
                        expected, sizeof(expected), &expected_size) && expected_size == sizeof(expected));
  CHECK(wallet_session_import(words, "TREZOR") == WalletError::Ok);
  CHECK(wallet_session_import(words, nullptr) == WalletError::InvalidArgument);
  CHECK(wallet_session_import_language(words, MnemonicLanguage::ChineseTraditional, "") == WalletError::InvalidMnemonic);
  CHECK(wallet_session_load_seed(actual) == WalletError::Ok && !memcmp(actual, expected, sizeof(expected)));
  char too_long[kBip39MaxPassphraseBytes + 2];
  memset(too_long, 'A', sizeof(too_long));
  too_long[sizeof(too_long) - 1] = 0;
  CHECK(wallet_session_import(words, too_long) == WalletError::InvalidArgument);
  CHECK(wallet_session_import(words, "\xc3") == WalletError::UnsupportedUnicode);
  CHECK(wallet_session_load_seed(actual) == WalletError::Ok && !memcmp(actual, expected, sizeof(expected)));
  CHECK(wallet_session_import(words, "\xc3\xa9") == WalletError::Ok);
  CHECK(wallet_session_load_seed(actual) == WalletError::Ok);
  CHECK(bip39_seed_from_english(words, "e\xcc\x81", expected) == WalletError::Ok && !memcmp(actual, expected, sizeof(expected)));
  too_long[kBip39MaxPassphraseBytes] = 0;
  CHECK(wallet_session_import(words, too_long) == WalletError::Ok);
  CHECK(wallet_session_load_seed(actual) == WalletError::Ok && memcmp(actual, expected, sizeof(expected)));
  CHECK(wallet_session_import(words, "") == WalletError::Ok);
  CHECK(wallet_session_load_seed(actual) == WalletError::Ok && memcmp(actual, expected, sizeof(expected)));
  memcpy(expected, actual, sizeof(expected));
  CHECK(wallet_session_import(words, " ") == WalletError::Ok);
  CHECK(wallet_session_load_seed(actual) == WalletError::Ok && memcmp(actual, expected, sizeof(expected)));
  wallet_session_clear();
  CHECK(wallet_session_load_seed(actual) != WalletError::Ok);
  for (auto byte : actual) CHECK(!byte);
  CHECK(codecs() && evm_registry_binding() && run_aeternity_self_tests());
  const auto *sol = find_network_profile("sol");
  HdPrivateNode master{};
  uint8_t seed[kSeedSize] = {};
  DerivedAddress address;
  memset(&address, 0xa5, sizeof(address));
  CHECK(sol && derive_address(master, seed, *sol, 0, 1, 0, &address) == WalletError::InvalidArgument);
  const auto *bytes = reinterpret_cast<const uint8_t *>(&address);
  for (size_t i = 0; i < sizeof(address); ++i) CHECK(bytes[i] == 0);
  const char *disabled_networks[] = {"hive",
#if !HEXWALLET_TEST_RYO_PHONE_PAYMENTS
    "ryo",
#endif
#if !HEXWALLET_TEST_ZANO_PHONE_PAYMENTS
    "zano",
#endif
  };
  for (const char *id : disabled_networks) {
    const auto *network = find_network_profile(id);
    CHECK(network);
    memset(&address, 0xa5, sizeof(address));
    CHECK(wallet_derive_for_display(master, seed, *network, 0, 0, 0, &address) == WalletError::InvalidArgument);
    for (size_t i = 0; i < sizeof(address); ++i) CHECK(bytes[i] == 0);
  }
  const auto *stark = find_network_profile("stark");
  CHECK(stark != nullptr);
  const auto custody = plan_key_custody(*stark, se051c2hq1_profile());
  CHECK(custody.scheme == KeyScheme::StarkEcdsa && !custody.se_can_sign &&
        custody.mcu_must_hold_key && strstr(custody.reason, "Stark curve") != nullptr);
  puts("security-regressions=pass");
  CHECK(run_wallet_link_self_test());
  puts("mutual-pairing-and-encrypted-link=pass");
  return true;
}
