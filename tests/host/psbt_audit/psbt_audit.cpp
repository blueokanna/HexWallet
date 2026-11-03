// Independent public-API regression harness. Public deterministic test seed only.
#include "BitcoinTransaction.h"
#include "WalletSecurity.h"
#include "WalletCustomTokens.h"
#include "TokenCalldata.h"
#include "EvmTransaction.h"
#include "ChainCommon.h"
#include <vector>
#include <cstdio>
#include <cstring>
#include <cstdlib>
using namespace hexwallet;
using Bytes = std::vector<uint8_t>;
static Bytes le(uint64_t n, unsigned count)
{
  Bytes b;
  while (count--)
  {
    b.push_back(uint8_t(n));
    n >>= 8;
  }
  return b;
}
static void append(Bytes &a, const Bytes &b) { a.insert(a.end(), b.begin(), b.end()); }
static void field(Bytes &b, const Bytes &key, const Bytes &value)
{
  if (key.size() >= 253 || value.size() >= 253)
    std::abort();
  b.push_back(uint8_t(key.size()));
  append(b, key);
  b.push_back(uint8_t(value.size()));
  append(b, value);
}
static HdPrivateNode master;
static Bytes pub, script, derivation;
static BitcoinChainParams chain = {"btc", nullptr, kBitcoinMainnet, SighashFamily::Bitcoin, 0};
struct Options
{
  bool previous_tx = false, previous_witness = false, wrong_previous_hash = false;
  bool tap = false, internal = false, bad_internal = false, duplicate_internal = false, leaf = false;
  int tap_hash = -1;
  bool v2 = true, amount = true, output_script = true, output_key = false;
  bool bad_output_key = false, duplicate_amount = false, duplicate_input = false;
  bool mix_versions = false, explicit_v0 = false, trailing = false, script_key_data = false, zero_height = false;
  int flags_size = 0, flags = 0, psbt_version = 2;
  uint32_t height = 0, sequence = 0xfffffffdU;
};
static Bytes fixture(const Options &o)
{
  Bytes previous, txid(32, 0x42);
  if (o.previous_tx)
  {
    Bytes body = {1};
    append(body, Bytes(32, 0x43));
    append(body, le(0, 4));
    body.push_back(0);
    append(body, le(0xffffffff, 4));
    body.push_back(1);
    append(body, le(100000, 8));
    body.push_back(uint8_t(script.size()));
    append(body, script);
    previous = le(2, 4);
    append(previous, body);
    append(previous, le(0, 4));
    bool single = chain.sighash == SighashFamily::GroestlLegacy;
    if (o.wrong_previous_hash)
      single = !single;
    if (!(single ? crypto_sha256 : crypto_double_sha256)(previous.data(), previous.size(), txid.data()))
      std::abort();
    if (o.previous_witness)
    {
      previous = le(2, 4);
      append(previous, {0, 1});
      append(previous, body);
      append(previous, {1, 1, 0x42});
      append(previous, le(0, 4));
    }
  }
  Bytes b = {'p', 's', 'b', 't', 255};
  if (o.v2)
  {
    field(b, {251}, le(o.psbt_version, 4));
    field(b, {2}, le(2, 4));
    field(b, {4}, {uint8_t(o.duplicate_input ? 2 : 1)});
    field(b, {5}, {1});
    if (o.flags_size)
      field(b, {6}, le(o.flags, o.flags_size));
  }
  if (!o.v2 || o.mix_versions)
  {
    Bytes tx = le(2, 4);
    tx.push_back(1);
    append(tx, txid);
    append(tx, le(0, 4));
    tx.push_back(0);
    append(tx, le(o.sequence, 4));
    tx.push_back(1);
    append(tx, le(99000, 8));
    tx.push_back(uint8_t(script.size()));
    append(tx, script);
    append(tx, le(0, 4));
    field(b, {0}, tx);
    if (o.explicit_v0)
      field(b, {251}, le(0, 4));
  }
  b.push_back(0);
  for (int i = 0; i < (o.duplicate_input ? 2 : 1); ++i)
  {
    Bytes utxo = le(100000, 8);
    utxo.push_back(uint8_t(script.size()));
    append(utxo, script);
    if (o.previous_tx)
      field(b, {0}, previous);
    else
      field(b, {1}, utxo);
    Bytes key = {uint8_t(o.tap ? 0x16 : 6)};
    append(key, o.tap ? Bytes(pub.begin() + 1, pub.end()) : pub);
    Bytes d = derivation;
    if (o.tap)
      d.insert(d.begin(), o.leaf ? 1 : 0);
    field(b, key, d);
    if (o.internal)
    {
      Bytes x(pub.begin() + 1, pub.end());
      if (o.bad_internal)
        x[0] ^= 1;
      field(b, {0x17}, x);
      if (o.duplicate_internal)
        field(b, {0x17}, x);
    }
    if (o.tap_hash >= 0)
      field(b, {3}, le(o.tap_hash, 4));
    if (o.v2)
    {
      field(b, {14}, txid);
      field(b, {15}, le(0, 4));
      field(b, {16}, le(o.sequence, 4));
      if (o.height || o.zero_height)
        field(b, {18}, le(o.height, 4));
    }
    b.push_back(0);
  }
  if (o.v2)
  {
    if (o.amount)
      field(b, {3}, le(99000, 8));
    if (o.duplicate_amount)
      field(b, {3}, le(99000, 8));
    if (o.output_script)
      field(b, o.script_key_data ? Bytes{4, 1} : Bytes{4}, script);
  }
  if (o.output_key)
  {
    Bytes key = {uint8_t(o.tap ? 7 : 2)};
    append(key, o.tap ? Bytes(pub.begin() + 1, pub.end()) : pub);
    Bytes d = derivation;
    if (o.bad_output_key)
      d[0] ^= 1;
    if (o.tap)
      d.insert(d.begin(), 0);
    field(b, key, d);
    if (o.tap)
      field(b, {5}, Bytes(pub.begin() + 1, pub.end()));
  }
  b.push_back(0);
  if (o.trailing)
    b.push_back(0);
  return b;
}
static unsigned failures = 0, checks = 0;
static void check(const char *name, bool ok)
{
  ++checks;
  if (!ok)
    ++failures;
  std::printf("%s: %s\n", name, ok ? "PASS" : "FAIL");
}
static TransactionError parse(const Options &o, BitcoinSigningRequest *r)
{
  const Bytes b = fixture(o);
  return bitcoin_parse_psbt(b.data(), b.size(), master, chain, r);
}
static void taproot_checks()
{
  HdPrivateNode child = {};
  uint8_t pk[33], output[32], digest[32];
  if (hd_private_derive_path(&master, "m/86'/0'/0'/1/0", &child) != WalletError::Ok ||
      public_key_from_private(child.private_key, pk) != WalletError::Ok ||
      taproot_bip86_output_key(pk + 1, output) != WalletError::Ok)
  {
    check("Taproot derive", false);
    return;
  }
  pub.assign(pk, pk + 33);
  script = {0x51, 32};
  script.insert(script.end(), output, output + 32);
  derivation.resize(4);
  for (uint32_t n : {0x80000056U, 0x80000000U, 0x80000000U, 1U, 0U})
    append(derivation, le(n, 4));
  for (bool version2 : {false, true})
  {
    Options o;
    o.tap = true;
    o.v2 = version2;
    o.internal = true;
    o.output_key = true;
    for (int hash : {-1, 0, 1})
    {
      o.tap_hash = hash;
      BitcoinSigningRequest req = {};
      const bool parsed = parse(o, &req) == TransactionError::Ok;
      check("BIP371 v0/v2 change ownership", parsed && req.outputs[0].wallet_owned && req.outputs[0].change);
      uint8_t signed_tx[512];
      size_t size = sizeof(signed_tx);
      const bool signed_ok = parsed && bitcoin_sign_request(req, master, signed_tx, &size) == TransactionError::Ok;
      check("BIP86 v0/v2 signature verifies", signed_ok && size > 70 &&
                                                  bitcoin_sighash_taproot(req, 0, hash == 1 ? 1 : 0, nullptr, 0, digest) == TransactionError::Ok &&
                                                  secp256k1_schnorr_verify(output, digest, signed_tx + size - 4 - (hash == 1 ? 65 : 64)));
    }
    o.tap_hash = 2;
    BitcoinSigningRequest req = {};
    check("reject unsafe tap sighash", parse(o, &req) == TransactionError::Unsupported);
    o.tap_hash = -1;
    o.bad_internal = true;
    check("reject wrong internal key", parse(o, &req) == TransactionError::WrongWallet);
    o.bad_internal = false;
    o.duplicate_internal = true;
    check("reject duplicate internal key", parse(o, &req) == TransactionError::DuplicateField);
    o.duplicate_internal = false;
    o.leaf = true;
    check("reject unsupported leaf derivation", parse(o, &req) != TransactionError::Ok);
    o.leaf = false;
    o.bad_output_key = true;
    check("reject false Taproot change", parse(o, &req) == TransactionError::WrongWallet);
    o.bad_output_key = false;
    chain.network_id = "ltc";
    check("reject unadmitted chain Taproot", parse(o, &req) != TransactionError::Ok);
    chain.network_id = "btc";
  }
  secure_zero(&child, sizeof(child));
}

static void network_path_checks()
{
  const Bytes fingerprint(derivation.begin(), derivation.begin() + 4);
  for (const char *id : {"ltc84", "grs84", "dgb84", "bch", "bsv", "xec", "grs", "ltc"})
  {
    const auto *network = find_network_profile(id);
    const auto *policy = find_network_signing_policy(id);
    if (!network || !policy)
    {
      check("fork registry", false);
      continue;
    }
    DerivedAddress address = {};
    uint8_t pk[33], hash[20];
    if (derive_address(master, nullptr, *network, 0, 1, 0, &address) != WalletError::Ok ||
        public_key_from_private(address.private_key, pk) != WalletError::Ok || !crypto_hash160(pk, 33, hash))
    {
      check("fork key derivation", false);
      clear_derived_address(&address);
      continue;
    }
    pub.assign(pk, pk + 33);
    script = {0, 20};
    if (network->bip_purpose == 44)
      script = {0x76, 0xa9, 20};
    script.insert(script.end(), hash, hash + 20);
    if (network->bip_purpose == 44)
      append(script, {0x88, 0xac});
    derivation = fingerprint;
    for (uint32_t n : {network->bip_purpose | 0x80000000U, network->derivation_coin_type | 0x80000000U, 0x80000000U, 1U, 0U})
      append(derivation, le(n, 4));
    chain = {network->id, network->encoding == AddressEncoding::CashAddr ? network->alt_hrp : nullptr, network->utxo, policy->family, policy->fork_id};
    for (bool v2 : {false, true})
    {
      Options o;
      o.v2 = v2;
      o.output_key = true;
      o.previous_tx = network->bip_purpose == 44 && policy->family != SighashFamily::ForkId;
      BitcoinSigningRequest req = {};
      bool parsed = parse(o, &req) == TransactionError::Ok;
      char name[96];
      snprintf(name, sizeof(name), "%s v%d uses registered coin type and change address", id, v2 ? 2 : 0);
      check(name, parsed && req.outputs[0].change && !strcmp(req.outputs[0].address, address.address));
      uint8_t out[512];
      size_t size = sizeof(out);
      check("fork signs with matching derivation", parsed && bitcoin_sign_request(req, master, out, &size) == TransactionError::Ok);
      if (o.previous_tx)
      {
        o.previous_witness = true;
        check("previous txid excludes witness using chain hash", parse(o, &req) == TransactionError::Ok);
        o.wrong_previous_hash = true;
        check("wrong chain previous-transaction hash rejected", parse(o, &req) != TransactionError::Ok);
        o.previous_witness = false;
        check("wrong non-witness transaction hash rejected", parse(o, &req) != TransactionError::Ok);
        o.wrong_previous_hash = false;
      }
      BitcoinChainParams saved = chain;
      chain = {"btc", nullptr, kBitcoinMainnet, SighashFamily::Bitcoin, 0};
      check("Bitcoin rejects fork path", parse(o, &req) != TransactionError::Ok);
      chain = saved;
      // A Bitcoin derivation cannot be relabelled as this network.
      Bytes saved_path = derivation;
      derivation[8] = 0;
      derivation[9] = 0;
      derivation[10] = 0;
      derivation[11] = 0x80;
      check("fork rejects Bitcoin path", parse(o, &req) != TransactionError::Ok);
      derivation = saved_path;
    }
    clear_derived_address(&address);
  }
  chain = {"btc", nullptr, kBitcoinMainnet, SighashFamily::Bitcoin, 0};
}

static Bytes rlp(const Bytes &value, bool list = false)
{
  if (!list && value.size() == 1 && value[0] < 128)
    return value;
  Bytes out;
  if (value.size() < 56)
    out.push_back(uint8_t((list ? 192 : 128) + value.size()));
  else
  {
    Bytes size;
    size_t n = value.size();
    while (n)
    {
      size.insert(size.begin(), uint8_t(n));
      n >>= 8;
    }
    out.push_back(uint8_t((list ? 247 : 183) + size.size()));
    append(out, size);
  }
  append(out, value);
  return out;
}
static Bytes nft_tx(const uint8_t *contract, const uint8_t *data, size_t size, uint8_t chain_id = 1)
{
  Bytes body;
  for (const Bytes &part : {Bytes{}, Bytes{0x3b, 0x9a, 0xca, 0}, Bytes{1, 0x86, 0xa0},
                            Bytes(contract, contract + 20), Bytes{}, Bytes(data, data + size), Bytes{chain_id}, Bytes{}, Bytes{}})
    append(body, rlp(part));
  return rlp(body, true);
}
static void nft_checks()
{
  custom_tokens_bind_store(CustomTokenStore{});
  const auto *network = find_network_profile("eth");
  DerivedAddress address = {};
  uint8_t from[20] = {}, to[20] = {0x22}, contract[20] = {0x33};
  uint8_t id[32] = {}, amount[32] = {}, data[256] = {};
  size_t from_size = 0;
  id[31] = 7;
  amount[31] = 3;
  const bool derived = network && derive_address(master, nullptr, *network, 0, 0, 0, &address) == WalletError::Ok &&
                       chain_parse_hex(address.address, from, sizeof(from), &from_size) && from_size == 20;
  check("NFT sender derivation", derived);
  clear_derived_address(&address);
  if (!derived)
    return;
  for (const auto standard : {CustomTokenStandard::EvmErc721, CustomTokenStandard::EvmErc1155})
  {
    const bool erc721 = standard == CustomTokenStandard::EvmErc721;
    check("register NFT collection", custom_token_add_nft("eth", contract, standard, "NFT", "Audit collection") == CustomTokenError::Ok);
    std::vector<uint8_t> blob(kCustomTokenBlobMax);
    size_t size = 0, count = 0;
    CustomTokenRecord restored[1] = {};
    check("NFT persistence roundtrip", custom_token_serialize(blob.data(), blob.size(), &size) &&
                                           custom_token_deserialize(blob.data(), size, restored, 1, &count) && count == 1 &&
                                           restored[0].standard == standard && restored[0].decimals == 0);
    const bool built = erc721 ? token_build_erc721_safe_transfer(from, to, id, data, sizeof(data)) : token_build_erc1155_safe_transfer(from, to, id, 3, data, sizeof(data));
    check("build NFT calldata", built);
    const size_t data_size = erc721 ? 100 : 196;
    Bytes tx = nft_tx(contract, data, data_size);
    EvmSigningRequest req = {};
    bool parsed = evm_parse_transaction(tx.data(), tx.size(), *network, master, 0, &req) == EvmTransactionError::Ok;
    check("NFT review ID and quantity", parsed && !strcmp(req.token_id_text, "7") &&
                                            !strcmp(req.amount_text, erc721 ? "1" : "3"));
    char review[kEvmReviewTextSize] = {};
    check("NFT unverified warning", parsed && evm_review_details(req, review, sizeof(review)) && strstr(review, "UNVERIFIED CUSTOM TOKEN"));
    uint8_t signed_tx[kEvmMaxSignedTransactionSize] = {};
    size_t signed_size = sizeof(signed_tx);
    check("NFT real ECDSA signing", parsed && evm_sign_transaction(req, master, signed_tx, &signed_size) == EvmTransactionError::Ok && signed_size > 0);
    tx = nft_tx(contract, data, data_size, 56);
    check("NFT wrong chain rejected", evm_parse_transaction(tx.data(), tx.size(), *network, master, 0, &req) == EvmTransactionError::WrongNetwork);
    data[16] ^= 1;
    tx = nft_tx(contract, data, data_size);
    check("NFT foreign owner rejected", evm_parse_transaction(tx.data(), tx.size(), *network, master, 0, &req) == EvmTransactionError::WrongWallet);
    data[16] ^= 1;
    custom_token_add("eth", contract, 20, "TOKEN", "Wrong standard", 18);
    tx = nft_tx(contract, data, data_size);
    check("NFT wrong declared standard rejected", evm_parse_transaction(tx.data(), tx.size(), *network, master, 0, &req) == EvmTransactionError::Unsupported);
    custom_token_remove("eth", contract, 20);
    check("NFT unregistered contract rejected", evm_parse_transaction(tx.data(), tx.size(), *network, master, 0, &req) == EvmTransactionError::Unsupported);
  }
  check("NFT non-EVM registration rejected", custom_token_add_nft("btc", contract, CustomTokenStandard::EvmErc721, "NFT", "Collection") == CustomTokenError::UnsupportedNetwork);
  check("NFT invalid standard rejected", custom_token_add_nft("eth", contract, CustomTokenStandard::EvmErc20, "NFT", "Collection") == CustomTokenError::InvalidArgument);
  bool fail_save = false;
  CustomTokenStore store = {&fail_save,
                            [](void *, CustomTokenRecord *, size_t, size_t *)
                            { return false; },
                            [](void *context, const CustomTokenRecord *, size_t)
                            { return !*static_cast<bool *>(context); }};
  custom_tokens_bind_store(store);
  check("NFT stored before failure", custom_token_add_nft("eth", contract, CustomTokenStandard::EvmErc721, "NFT", "Original") == CustomTokenError::Ok);
  fail_save = true;
  check("NFT failed update rolls back", custom_token_add_nft("eth", contract, CustomTokenStandard::EvmErc1155, "NEW", "Changed") == CustomTokenError::StorageFailure &&
                                            custom_token_find("eth", contract, 20)->standard == CustomTokenStandard::EvmErc721);
  check("NFT failed removal rolls back", custom_token_remove("eth", contract, 20) == CustomTokenError::StorageFailure && custom_token_count() == 1);
  contract[0] ^= 1;
  check("NFT failed insertion rolls back", custom_token_add_nft("eth", contract, CustomTokenStandard::EvmErc721, "NFT", "Other") == CustomTokenError::StorageFailure && custom_token_count() == 1);
  custom_tokens_bind_store(CustomTokenStore{});
}
int main()
{
  uint8_t seed[32] = {};
  for (unsigned i = 0; i < 32; ++i)
    seed[i] = uint8_t(i);
  HdPrivateNode child = {};
  uint8_t pk[33], hash[20];
  if (hd_private_from_seed(seed, sizeof(seed), &master) != WalletError::Ok ||
      hd_private_derive_path(&master, "m/84'/0'/0'/0/0", &child) != WalletError::Ok ||
      public_key_from_private(master.private_key, pk) != WalletError::Ok ||
      !crypto_hash160(pk, 33, hash))
    return 2;
  derivation.assign(hash, hash + 4);
  for (uint32_t n : {0x80000054U, 0x80000000U, 0x80000000U, 0U, 0U})
    append(derivation, le(n, 4));
  if (public_key_from_private(child.private_key, pk) != WalletError::Ok || !crypto_hash160(pk, 33, hash))
    return 2;
  pub.assign(pk, pk + 33);
  script = {0, 20};
  script.insert(script.end(), hash, hash + 20);
  Options base;
  BitcoinSigningRequest v0 = {}, v2 = {};
  Options o = base;
  o.v2 = false;
  check("valid v0", parse(o, &v0) == TransactionError::Ok);
  o.explicit_v0 = true;
  check("explicit v0", parse(o, &v0) == TransactionError::Ok);
  const bool v2ok = parse(base, &v2) == TransactionError::Ok;
  check("valid v2", v2ok);
  uint8_t a[512] = {}, b[512] = {};
  size_t an = sizeof(a), bn = sizeof(b);
  check("v0/v2 identical signed transaction", v2ok &&
                                                  bitcoin_sign_request(v0, master, a, &an) == TransactionError::Ok &&
                                                  bitcoin_sign_request(v2, master, b, &bn) == TransactionError::Ok && an == bn && !memcmp(a, b, an));
  o = base;
  o.flags_size = 1;
  check("one-byte modifiable flags", parse(o, &v2) == TransactionError::Ok);
  o.flags_size = 4;
  check("reject four-byte flags", parse(o, &v2) != TransactionError::Ok);
  o = base;
  o.output_key = true;
  check("output ownership checked", parse(o, &v2) == TransactionError::Ok && v2.outputs[0].wallet_owned);
  o.bad_output_key = true;
  check("reject false output ownership", parse(o, &v2) == TransactionError::WrongWallet);
  o = base;
  o.amount = false;
  check("reject missing amount", parse(o, &v2) == TransactionError::MissingField);
  o = base;
  o.output_script = false;
  check("reject missing script", parse(o, &v2) == TransactionError::MissingField);
  o = base;
  o.duplicate_amount = true;
  check("reject duplicate amount", parse(o, &v2) == TransactionError::DuplicateField);
  o = base;
  o.duplicate_input = true;
  check("reject duplicate outpoint", parse(o, &v2) == TransactionError::DuplicateField);
  o = base;
  o.psbt_version = 1;
  check("reject undefined PSBT v1", parse(o, &v2) == TransactionError::Unsupported);
  o = base;
  o.mix_versions = true;
  check("reject v2 unsigned transaction", parse(o, &v2) != TransactionError::Ok);
  o = base;
  o.trailing = true;
  check("reject trailing data", parse(o, &v2) == TransactionError::NonCanonical);
  o = base;
  o.height = 100;
  check("required height applied", parse(o, &v2) == TransactionError::Ok && v2.lock_time == 100);
  o.sequence = 0xffffffffU;
  check("reject ineffective required locktime", parse(o, &v2) != TransactionError::Ok);
  o = base;
  o.zero_height = true;
  check("reject zero required height", parse(o, &v2) == TransactionError::NonCanonical);
  o = base;
  o.script_key_data = true;
  check("reject script key data", parse(o, &v2) == TransactionError::NonCanonical);
  o = base;
  o.sequence = 0xffffffffU;
  check("final sequence without constraint allowed", parse(o, &v2) == TransactionError::Ok);
  o = base;
  o.tap_hash = 0;
  check("reject DEFAULT sighash on non-Taproot v2", parse(o, &v2) == TransactionError::Unsupported);
  o.v2 = false;
  check("reject DEFAULT sighash on non-Taproot v0", parse(o, &v2) == TransactionError::Unsupported);
  // A failed parse must not partially overwrite a previously approved request.
  memset(&v2, 0xa5, sizeof(v2));
  BitcoinSigningRequest before = v2;
  o = base;
  o.psbt_version = 1;
  parse(o, &v2);
  check("failure preserves caller output", memcmp(&before, &v2, sizeof(v2)) == 0);
  const struct
  {
    const char *id;
    uint32_t chain_id;
  } networks[] = {
      {"bsc", 56}, {"matic", 137}, {"flare", 14}, {"arb1", 42161}, {"avaxc", 43114}, {"arc", 5042}, {"aurora", 1313161554}, {"ftm", 250}, {"bitlayer", 200901}, {"base", 8453}, {"xlayer", 196}, {"rsk", 30}};
  const uint8_t contract[20] = {0x42};
  for (const auto &n : networks)
  {
    const auto *profile = find_network_profile(n.id);
    check(n.id, profile && profile->evm_chain_id == n.chain_id &&
                    profile->encoding == AddressEncoding::Evm &&
                    custom_token_add(n.id, contract, 20, "AUDIT", "Audit fixture", 6) == CustomTokenError::Ok &&
                    custom_token_find(n.id, contract, 20) != nullptr);
  }
  check("custom token storage regressions", run_custom_token_self_tests());
  check("token calldata regressions", run_token_calldata_self_tests());
  nft_checks();
  taproot_checks();
  network_path_checks();
  check("Bitcoin internal regressions", run_bitcoin_transaction_self_test());
  std::printf("Bitcoin stage: %d\n", bitcoin_self_test_stage());
  check("EVM internal regressions", run_evm_transaction_self_test());
  secure_zero(&master, sizeof(master));
  secure_zero(&child, sizeof(child));
  std::printf("%u checks, %u failures\n", checks, failures);
  return failures ? 1 : 0;
}
