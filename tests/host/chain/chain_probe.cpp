#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include "ChainCommon.h"
#include "CryptoNoteTransaction.h"
#include "BeamOutput.h"
#include "BeamAddress.h"
#include "XelisAccount.h"
#include "QuantusTransaction.h"
#include "MlDsa87.h"
#include "Blake2b.h"
#include "BeamPayment.h"
#include "ChainTransaction.h"
#include "BitcoinTransaction.h"
#include "CosmosTransaction.h"
#include "WalletAltAddresses.h"
#include "WalletEngine.h"
#include "WalletSecurity.h"
#include "PolkadotTransaction.h"
#include "BlsG2.h"
#include "WalletNetworks.h"
#include "WalletCatalog.h"
#include "ZcashTransaction.h"
#include "DashTransaction.h"
#include "EvmTransaction.h"
#include "QrlXmss.h"
#include "StarknetTransaction.h"
using namespace hexwallet;
static void hex(const char *key, const uint8_t *p, size_t n) {
  printf("%s=", key); for (size_t i = 0; i < n; ++i) printf("%02x", p[i]); puts("");
}
int main(int argc, char **argv) {
  if (argc == 2 && !strcmp(argv[1], "primary-assets")) {
    const char *ids[] = {"btc","eth","ada","dash","xmr","zec","avaxc","bch","bsv","bsc","doge","etc",
      "ftm","rvn","ltc","dgb","firo","erg","cfx","vtc","dcr","qrl","fork_utxo_raptoreum","xch"};
    const uint8_t seed[64]{};
    HdPrivateNode master{};
    if (hd_private_from_seed(seed,sizeof(seed),&master) != WalletError::Ok) return 1;
    for (const char *id : ids) {
      WalletCatalogEntry entry{};
      DerivedAddress address{};
      if (!wallet_catalog_find(id,&entry) || !entry.network ||
          !wallet_catalog_has(entry,WalletCapabilityAddress) || !wallet_catalog_has(entry,WalletCapabilitySigning) ||
          !wallet_catalog_has(entry,WalletCapabilityTransactionReview) ||
          derive_address(master,seed,*entry.network,0,0,0,&address) != WalletError::Ok ||
          !address.address[0] || !address.path[0]) {
        printf("primary-asset-failed=%s\n",id);
        return 1;
      }
      clear_derived_address(&address);
    }
    secure_zero(&master,sizeof(master));
    puts("primary-asset-addresses-and-capabilities=24/24");
    return 0;
  }
  if (argc == 2 && !strcmp(argv[1], "quantus-signature-kat")) {
    uint8_t seed[32], rnd[32]{}, pk[kMlDsa87PublicKeySize], sk[kMlDsa87SecretKeySize];
    uint8_t sig[kMlDsa87SignatureSize], actual[32], expected[32];
    size_t length;
    // quantus-wasm ext.rs, signature_is_deterministic_known_value. The
    // production signer supplies a fresh hedge; the published KAT uses zero.
    memset(seed,7,32);
    const uint8_t msg[] = "\x00\x11" "QUANTUS_EXTRINSIC" "quantus deterministic signature vector";
    if (!ml_dsa_87_keypair_from_seed(seed,pk,sk) || !ml_dsa_87_sign(sk,msg,sizeof(msg)-1,rnd,sig) ||
        !ml_dsa_87_verify(pk,msg,sizeof(msg)-1,sig) ||
        !blake2b_keyed_hash(nullptr,0,sig,sizeof(sig),actual,32) ||
        !chain_parse_hex("2ddb9d1e2fffa950cb7bd003bd34abf35b56cc0c99f1a703a77b5c54f4de017e",expected,32,&length) ||
        memcmp(actual,expected,32)) return 1;
    puts("quantus-official-signature=pass");
    return 0;
  }
  if (argc == 5 && !strcmp(argv[1], "quantus-extrinsic-kat")) {
    uint8_t seed[64], input[180], reference[kChainMaxSignedSize], generated[sizeof(reference)];
    size_t seed_size, size;
    if (!chain_parse_hex(argv[2],seed,64,&seed_size) || seed_size!=64 ||
        !chain_parse_hex(argv[3],input,sizeof(input),&size)) return 1;
    FILE *f = fopen(argv[4],"rb");
    if (!f) return 1;
    const size_t n = fread(reference,1,sizeof(reference),f);
    const bool complete = feof(f) && !ferror(f);
    fclose(f);
    HdPrivateNode master{};
    ChainTransaction tx{};
    size_t capacity = sizeof(generated);
    constexpr size_t sig = 37, pk = sig+kMlDsa87SignatureSize;
    if (!complete || n <= pk+kMlDsa87PublicKeySize || hd_private_from_seed(seed,64,&master)!=WalletError::Ok ||
        chain_review_transaction(ChainFamily::Quantus,input,size,master,seed,0,&tx)!=ChainError::Ok ||
        chain_sign_transaction(tx,master,seed,generated,&capacity)!=ChainError::Ok || n!=capacity ||
        memcmp(reference,generated,sig) || memcmp(reference+pk,generated+pk,n-pk)) return 1;
    uint8_t message[2+17+sizeof(input)] = {0,17};
    memcpy(message+2,"QUANTUS_EXTRINSIC",17);
    memcpy(message+19,input,size);
    if (!ml_dsa_87_verify(reference+pk,message,size+19,reference+sig) ||
        !ml_dsa_87_verify(generated+pk,message,size+19,generated+sig)) return 1;
    input[size-73] ^= 1;
    if (chain_review_transaction(ChainFamily::Quantus,input,size,master,seed,0,&tx)!=ChainError::RuntimeMismatch) return 1;
    puts("quantus-upstream-extrinsic=pass");
    return 0;
  }
  if (argc == 2 && !strcmp(argv[1], "xelis-native-account")) {
    // Upstream mixed-case English and Chinese recovery regression phrases.
    const char *phrase = "KiNG gleeFuL fidgET furnished agreed rowboat factual echo scrub enforce bygones muzzle mews abbey swiftly issued tonic cinema lettuce zapped sighting kettle leopard logic enforce";
    uint8_t key[32], expected[32], pk[32], sig[64];
    size_t length;
    char addr[80];
    const uint8_t msg[] = "HexWallet XELIS interoperability";
    if (!xelis_recover_private_key(phrase,key) ||
        !chain_parse_hex("9c5115f46bb47eb5f1506a864968c56bb74b15d38d3581494de587c8a889f103",expected,32,&length) ||
        memcmp(key,expected,32) || !xelis_account(key,pk,addr,sizeof(addr)) ||
        strcmp(addr,"xel:8e2mnl54m853uhy658s4xnqrrjl9cfx9u00tnenw0k3r4esmfyzsqt7skup") ||
        !xelis_public_key_from_address(addr,expected) || memcmp(pk,expected,32) ||
        !chain_parse_hex("925cc112458e289b92d0363b24ee1fb7b83b24b8518b357fd1c8ea198cabb50f155f4a2ad69fde1d28886eace145e34f598e38ea1a31ca8a77d85f48f52a8705",sig,64,&length) ||
        !xelis_verify_message(pk,msg,sizeof(msg)-1,sig) || xelis_verify_message(pk,msg,sizeof(msg),sig) ||
        !xelis_sign_message(key,msg,sizeof(msg)-1,sig) || !xelis_verify_message(pk,msg,sizeof(msg)-1,sig)) return 1;
    std::string invalid = std::string(phrase).substr(0,strlen(phrase)-7) + "abbey";
    if (xelis_recover_private_key(invalid.c_str(),key)) return 1;
    addr[62] = 'q';
    if (xelis_public_key_from_address(addr,expected)) return 1;
    if (!xelis_recover_private_key("的 一 是 在 不 了 有 和 人 这 中 大 为 上 个 国 我 以 要 他 时 来 用 们",key)) return 1;
    puts("xelis-native-account=pass");
    return 0;
  }
  if (argc == 2 && !strcmp(argv[1], "beam-regular-address")) {
    uint8_t seed[64]{}, endpoint[32], decoded[32];
    char token[kBeamRegularAddressSize];
    if (!beam_regular_address(seed, 1, token) || !beam_endpoint(seed, 1, endpoint) ||
        !beam_regular_recipient(token, decoded) || memcmp(decoded, endpoint, 32) ||
        strcmp(token, "M4Z8DsWS5UmeeYuGK54qXJ2DerBmz14KSHgFArB9jMjHoVrfwArhim7smSnfRpF51tmj9pnNW78cVfvBmFgyUU9zV3gcMkhTHvcsoMBDtm3VTaJgahPCN32CZLB")) return 1;
    puts(token);
    return 0;
  }
  if (argc == 3 && !strcmp(argv[1], "zephyr-mainnet")) {
    uint8_t wire[kCryptoNoteMaxTxBytes], encoded[sizeof(wire)], hash[32], expected[32];
    FILE *f = fopen(argv[2], "rb");
    if (!f) return 1;
    const size_t size = fread(wire, 1, sizeof(wire), f);
    const bool complete = feof(f) && !ferror(f);
    fclose(f);
    CryptoNoteTransaction tx{};
    size_t written = sizeof(encoded), n = 0;
    const auto network = CryptoNoteReviewNetwork::ZephyrMainnet;
    if (!complete || !chain_parse_hex("7e2f3d9d1b5deaf3db873d5fe5d6c54272d127a84aa04ddc18bd46e66a9a7c12", expected, 32, &n) ||
        cryptonote_parse_transaction(wire, size, &tx) == CryptoNoteTxError::Ok ||
        cryptonote_parse_transaction(wire, size, &tx, network) != CryptoNoteTxError::Ok ||
        tx.rct.type != 6 || tx.rct.fee != 445600000 || tx.input_count != 2 || tx.output_count != 2 ||
        cryptonote_transaction_hash(tx, hash) != CryptoNoteTxError::Ok || memcmp(hash, expected, 32) ||
        cryptonote_serialize_transaction(tx, encoded, &written) != CryptoNoteTxError::Ok ||
        size != written || memcmp(wire, encoded, size) || !cryptonote_transaction_balance_ok(tx)) return 1;
    // Change one byte in the first input asset. The parser must reject other
    // assets even though they use the same public-key and commitment encoding.
    if (wire[5] != 3 || memcmp(wire+6,"ZPH",3)) return 1;
    wire[7] = 'S';
    if (cryptonote_parse_transaction(wire, size, &tx, network) == CryptoNoteTxError::Ok) return 1;
    puts("zephyr-mainnet=pass");
    return 0;
  }
  if ((argc == 2 || argc == 3) && !strcmp(argv[1], "beam-output-selftest")) {
    const BeamCoin expected{17, BeamCoinType::Regular, 2, 123456789};
    BeamCoin found{};
    uint8_t seed[64]{};
    BeamOutput output{};
    if (!beam_create_output(seed, expected, output) || !beam_recover_output(seed, output, found) ||
        found.index != expected.index || found.type != expected.type ||
        found.subkey != expected.subkey || found.groth != expected.groth) return 1;
    // Beam's independent hw_crypto CoinID_getSkComm with the SHA256 of a
    // public 64-byte zero seed and CoinID(17, norm, 0x03000002, 123456789, 0).
    uint8_t reference[33];
    size_t n;
    if (!chain_parse_hex("05d49abaeecfebf10a74b287d60c5212b28d6abdfb4b021cee05513f8fd27bdfbb",
          reference, sizeof(reference), &n) || memcmp(reference, &output, 33)) return 1;
    if (argc == 3) {
      FILE *file = fopen(argv[2], "wb");
      if (!file) return 1;
      const bool ok = fwrite(&output, 1, sizeof(output), file) == sizeof(output);
      if (fclose(file) || !ok) return 1;
    }
    seed[0] ^= 1;
    if (beam_recover_output(seed, output, found) || found.groth) return 1;
    output.proof[64] ^= 1;
    if (beam_verify_output(output)) return 1;
    BeamOffer offer{expected.groth, 100000, 4000000, 4000100};
    uint8_t sender_seed[64]{};
    if (!beam_endpoint(sender_seed, 1, offer.sender) || !beam_endpoint(seed, 1, offer.receiver) ||
        !chain_parse_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800",
                         offer.sender_excess, 33, &n) ||
        !chain_parse_hex("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee500",
                         offer.sender_nonce, 33, &n)) return 1;
    BeamReceiverReply reply{};
    if (!beam_receive(seed, 1, offer, reply) || !beam_verify_receiver(offer, reply) ||
        !beam_recover_output(seed, reply.output, found) || found.groth != expected.groth) return 1;
    ++offer.fee;
    if (beam_verify_receiver(offer, reply)) return 1;
    --offer.fee;
    reply.offset[31] ^= 1;
    if (beam_verify_receiver(offer, reply)) return 1;
    reply.offset[31] ^= 1;
    reply.payment_confirmation[40] ^= 1;
    if (beam_verify_receiver(offer, reply)) return 1;
    output.proof[64] ^= 1;
    BeamSender sender;
    uint8_t recipient[32];
    memcpy(recipient, offer.receiver, 32);
    if (!sender.begin(sender_seed, 1, recipient, output, 100000000, 100000, 4000000, 4000100, offer) ||
        !beam_receive(seed, 1, offer, reply)) return 1;
    uint8_t offer_wire[kBeamOfferSize];
    BeamOffer decoded{};
    beam_encode_offer(offer, offer_wire);
    if (!beam_decode_offer(offer_wire, decoded) || !beam_verify_receiver(decoded, reply)) return 1;
    BeamSignedTransfer tx;
    if (!sender.finish(reply, tx) || tx.size <= 2 * sizeof(BeamOutput)) return 1;
    BeamOutput outputs[2];
    memcpy(outputs, tx.bytes + 41, sizeof(outputs));
    unsigned changes = 0, payments = 0;
    for (const auto &o : outputs) {
      if (beam_recover_output(sender_seed, o, found)) {
        if (found.type != BeamCoinType::Change || found.groth != 23356789) return 1;
        ++changes;
      }
      if (beam_recover_output(seed, o, found)) {
        if (found.type != BeamCoinType::Regular || found.groth != 100000000) return 1;
        ++payments;
      }
    }
    if (changes != 1 || payments != 1) return 1;
    if (argc == 3) {
      std::string path = std::string(argv[2]) + ".tx";
      FILE *file = fopen(path.c_str(), "wb");
      if (!file) return 1;
      const bool ok = fwrite(tx.bytes, 1, tx.size, file) == tx.size;
      if (fclose(file) || !ok) return 1;
    }
    if (sender.finish(reply, tx) || tx.size) return 1;
    if (sender.begin(sender_seed, 1, recipient, output, UINT64_MAX, 100000, 4000000, 4000100, offer) ||
        sender.begin(sender_seed, 1, recipient, output, 1, UINT64_MAX, 4000000, 4000100, offer) ||
        sender.begin(sender_seed, 1, recipient, output, 1, 45999, 4000000, 4000100, offer) ||
        sender.begin(sender_seed, 1, recipient, output, 1, 100000, 4000100, 4000000, offer) ||
        sender.begin(seed, 1, recipient, output, 1, 100000, 4000000, 4000100, offer)) return 1;
    // Spending the exact remainder creates a single receiver output. Check
    // the minimum fee for this shape and recover the full credited amount.
    if (!sender.begin(sender_seed, 1, recipient, output, expected.groth - 28000,
                      28000, 4000000, 4000100, offer) || sender.change_amount() ||
        !beam_receive(seed, 1, offer, reply) || !sender.finish(reply, tx) || tx.size < 41 + sizeof(BeamOutput) ||
        memcmp(tx.bytes + 37, "\x00\x00\x00\x01", 4)) return 1;
    memcpy(&outputs[0], tx.bytes + 41, sizeof(BeamOutput));
    if (!beam_recover_output(seed, outputs[0], found) || found.groth != expected.groth - 28000) return 1;
    if (!sender.begin(sender_seed, 1, recipient, output, expected.groth - 100000,
                      100000, 4000000, 4000100, offer) || !beam_receive(seed, 1, offer, reply)) return 1;
    reply.partial_signature[15] ^= 1;
    if (sender.finish(reply, tx) || tx.size) return 1;
    reply.partial_signature[15] ^= 1;
    if (sender.finish(reply, tx) || tx.size) return 1;
    puts("beam-output=pass");
    return 0;
  }
  if (argc == 2 && !strcmp(argv[1], "alph-zeph-selftest")) {
    // alephium-web3 c457e9f, packages/web3-wallet/src/hd-wallet.test.ts.
    const char *phrase = "vault alarm sad mass witness property virus style good flower rice alpha viable evidence run glare pretty scout evil judge enroll refuse another lava";
    const NetworkProfile *alph = find_network_profile("alph");
    const NetworkProfile *zeph = find_network_profile("zeph");
    const NetworkProfile *xmr = find_network_profile("xmr");
    HdPrivateNode master{};
    DerivedAddress derived{};
    uint8_t seed[64], expected[32], spend[32], view[32], xm_spend[32], xm_view[32];
    size_t n;
    bool ok = alph && zeph && xmr && bip39_seed_from_english(phrase, "Alephium", seed) == WalletError::Ok &&
              hd_private_from_seed(seed, sizeof(seed), &master) == WalletError::Ok &&
              chain_parse_hex("ff8efb234d82f49ece8b34fa9a7250e16879a7a8a222463390159e2e51a1a117", expected, 32, &n) &&
              derive_address(master, seed, *alph, 0, 0, 1, &derived) == WalletError::Ok &&
              memcmp(derived.private_key, expected, 32) == 0 &&
              derive_cryptonote_keys(master, *zeph, 0, 0, 1, spend, view) == WalletError::Ok &&
              derive_cryptonote_keys(master, *xmr, 0, 0, 1, xm_spend, xm_view) == WalletError::Ok &&
              !memcmp(spend, xm_spend, 32) && !memcmp(view, xm_view, 32) &&
              derive_address(master, seed, *zeph, 0, 0, 1, &derived) == WalletError::Ok &&
              !strncmp(derived.address, "ZEPHs", 5) &&
              derive_address(master, seed, *zeph, 0, 0, 0, &derived) == WalletError::Ok &&
              !strncmp(derived.address, "ZEPHYR", 6);
    printf("alph-zeph=%s\n", ok ? "pass" : "FAIL");
    return ok ? 0 : 1;
  }
  if (argc == 2 && !strcmp(argv[1], "quantus-selftest")) {
    // quantus-wasm 04174ffc test/smoke.test.js, accountFromMnemonic.
    uint8_t seed[64];
    HdPrivateNode master{};
    DerivedAddress address{};
    const NetworkProfile *network = find_network_profile("quantus");
    const bool ok = network && bip39_seed_from_english(
        "human snow truck virus now jaguar wall brisk shoe craft gravity diesel", "", seed) == WalletError::Ok &&
        derive_address(master, seed, *network, 0, 0, 0, &address) == WalletError::Ok &&
        !strcmp(address.address, "qznQKhufTDfU3szAzfgCny7wMhxUN3qjEqneiRUNgC7MjSDyG");
    printf("quantus=%s\n", ok ? "pass" : "FAIL");
    return ok ? 0 : 1;
  }
  // BIP39/BIP32/BIP84/secp256k1/BIP340 against the real curve code. The host
  // suite links a stub, so this is the only place those pinned vectors actually
  // execute; it is also what proves the in-tree ECDSA/BIP340 engine matches the
  // published answers instead of merely compiling.
  if (argc == 2 && !strcmp(argv[1], "wallet-selftest")) {
    const bool bip39 = run_bip39_self_test();
    const bool bip32 = run_bip32_self_test();
    const bool bip84 = run_bip84_self_test();
    const bool evm_derive = run_evm_derivation_self_test();
    const bool secp256k1 = run_secp256k1_self_test();
    const bool bip340 = run_bip340_self_test();
    printf("wallet bip39=%s bip32=%s bip84=%s evm-derive=%s secp256k1=%s bip340=%s\n",
           bip39 ? "pass" : "FAIL", bip32 ? "pass" : "FAIL",
           bip84 ? "pass" : "FAIL", evm_derive ? "pass" : "FAIL",
           secp256k1 ? "pass" : "FAIL", bip340 ? "pass" : "FAIL");
    return bip39 && bip32 && bip84 && evm_derive && secp256k1 && bip340 ? 0 : 1;
  }
  if (argc == 2 && !strcmp(argv[1], "dash-sign-selftest")) {
    const bool ok = run_dash_self_tests() && run_dash_signature_self_test();
    printf("dash-sign=%s\n", ok ? "pass" : "FAIL");
    return ok ? 0 : 1;
  }
  // PSBT v0 and v2 parsing plus the final signature need BIP32 derivation and
  // ECDSA, so they only run where the real curve code is linked. The stubbed
  // host harness never gets this far, which is why it is a distinct mode.
  if (argc == 2 && !strcmp(argv[1], "bitcoin-tx-selftest")) {
    const bool ok = run_bitcoin_transaction_self_test();
    printf("bitcoin-tx=%s\n", ok ? "pass" : "FAIL");
    if (!ok) printf("bitcoin-stage=%d\n", bitcoin_self_test_stage());
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
  // Starknet needs real BIP32/Stark arithmetic: the main host suite derives no
  // keys, so the profile -> encoder mapping is checked here.
  if (argc == 2 && !strcmp(argv[1], "stark-selftest")) {
    uint8_t seed[64] = {};
    for (size_t index = 0; index < sizeof(seed); ++index) {
      seed[index] = static_cast<uint8_t>(index * 3 + 1);
    }
    HdPrivateNode master = {};
    DerivedAddress stark = {};
    const NetworkProfile *network = find_network_profile("stark");
    bool ok = network != nullptr && network->encoding == AddressEncoding::StarknetKey &&
              hd_private_from_seed(seed, sizeof(seed), &master) == WalletError::Ok &&
              derive_address(master, seed, *network, 0, 0, 0, &stark) ==
                  WalletError::Ok;
    if (ok) {
      uint8_t private_key[kStarknetFeltSize] = {};
      uint8_t public_key[kStarknetFeltSize] = {};
      char text[kStarknetAddressTextSize] = {};
      ok = starknet_key_pair(stark.private_key, private_key, public_key) &&
           starknet_felt_text(public_key, text, sizeof(text)) &&
           strcmp(text, stark.address) == 0 &&
           strlen(stark.address) == kStarknetAddressTextSize - 1;
      // The account address must be the SNIP-5 address of this key, not a value
      // the host could substitute.
      uint8_t class_hash[kStarknetFeltSize] = {};
      uint8_t salt[kStarknetFeltSize] = {};
      uint8_t account[kStarknetFeltSize] = {};
      class_hash[kStarknetFeltSize - 1] = 0x21;
      salt[kStarknetFeltSize - 1] = 0x42;
      const bool address_ok =
          starknet_account_address(class_hash, salt, public_key, account);
      uint8_t other[kStarknetFeltSize] = {};
      salt[kStarknetFeltSize - 1] = 0x43;
      ok = ok && address_ok &&
           starknet_account_address(class_hash, salt, public_key, other) &&
           !crypto_constant_time_equal(account, other, kStarknetFeltSize);
      memset(private_key, 0, sizeof(private_key));
      memset(public_key, 0, sizeof(public_key));
      memset(account, 0, sizeof(account));
      memset(other, 0, sizeof(other));
    }
    printf("path=%s\naddress=%s\n", stark.path, stark.address);
    printf("stark-derivation=%s\n", ok ? "pass" : "FAIL");
    clear_derived_address(&stark);
    memset(&master, 0, sizeof(master));
    memset(seed, 0, sizeof(seed));
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
  uint8_t output[kChainMaxSignedSize]; memset(output, 0xa5, sizeof(output));
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
