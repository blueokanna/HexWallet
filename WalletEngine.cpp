#include "WalletEngine.h"
#include "SolanaDerivation.h"
#include "StellarTransaction.h"
#include "AlgorandTransaction.h"
#include "NearTransaction.h"
#include "TezosTransaction.h"
#include "SuiTransaction.h"

#include <stdio.h>
#include <string.h>

#include "CryptoExtended.h"
#include "CardanoDerivation.h"
#include "HederaTransaction.h"
#include "SiaTransaction.h"
#include "NemTransaction.h"
#include "IcpTransaction.h"
#include "CryptoNoteAddress.h"
#include "CryptoPrimitives.h"
#include "QrlXmss.h"
#include "WalletAddresses.h"
#include "WalletAltAddresses.h"

namespace hexwallet {

static_assert(kAddressTextSize >= kCryptoNoteStandardAddressSize,
              "DerivedAddress must hold a CryptoNote standard address");

namespace {

CryptoNoteAddressProfile cryptonote_profile_for(const NetworkProfile &network) {
  if (network.cryptonote_profile != nullptr) return *network.cryptonote_profile;
  return {network.account_version, network.cryptonote_integrated_prefix,
          network.cryptonote_subaddress_prefix};
}

// Build the display derivation path for a network style.
bool build_path_text(const NetworkProfile &network, uint32_t account,
                     uint32_t change, uint32_t address_index, char *path,
                     size_t path_size) {
  int written = 0;
  switch (network.derivation) {
    case DerivationStyle::NearSlip10:
      if (account != 0 || change != 0) return false;
      written = snprintf(path, path_size, "m/44'/397'/%lu'", static_cast<unsigned long>(address_index));
      break;
    case DerivationStyle::StellarSep5:
      if (account != 0 || change != 0) return false;
      written = snprintf(path, path_size, "m/44'/148'/%lu'",
                         static_cast<unsigned long>(address_index));
      break;
    case DerivationStyle::Bip44:
      written = snprintf(path, path_size, "m/%lu'/%lu'/%lu'/%lu/%lu",
                         static_cast<unsigned long>(network.bip_purpose),
                         static_cast<unsigned long>(network.derivation_coin_type),
                         static_cast<unsigned long>(account),
                         static_cast<unsigned long>(change),
                         static_cast<unsigned long>(address_index));
      break;
    case DerivationStyle::AllHardenedBip44:
      written = snprintf(path, path_size, "m/44'/%lu'/%lu'/%lu'/%lu'",
                         static_cast<unsigned long>(network.derivation_coin_type),
                         static_cast<unsigned long>(account),
                         static_cast<unsigned long>(change),
                         static_cast<unsigned long>(address_index));
      break;
    case DerivationStyle::SolanaBip44:
      written = snprintf(path, path_size, "m/44'/%lu'/%lu'/0'/%lu'",
                         static_cast<unsigned long>(network.derivation_coin_type),
                         static_cast<unsigned long>(account),
                         static_cast<unsigned long>(address_index));
      break;
    case DerivationStyle::CardanoBip1852:
      written = snprintf(path, path_size, "m/1852'/%lu'/%lu'/%lu/%lu",
                         static_cast<unsigned long>(network.derivation_coin_type),
                         static_cast<unsigned long>(account),
                         static_cast<unsigned long>(change),
                         static_cast<unsigned long>(address_index));
      break;
    case DerivationStyle::ChiaEip2333:
      written = snprintf(path, path_size, "m/12381'/%lu'/0'/%lu'",
                         static_cast<unsigned long>(network.derivation_coin_type),
                         static_cast<unsigned long>(address_index));
      break;
    case DerivationStyle::QrlXmss:
      written = snprintf(path, path_size, "qrl-xmss/h%u/%lu",
                         static_cast<unsigned>(kQrlDefaultHeight),
                         static_cast<unsigned long>(address_index));
      break;
  }
  return written > 0 && static_cast<size_t>(written) < path_size;
}

// SLIP-0010 index array for an ed25519 network (all hardened).
bool build_slip10_path(const NetworkProfile &network, uint32_t account,
                       uint32_t change, uint32_t address_index,
                       uint32_t path[6], size_t *out_size) {
  uint32_t local[6];
  size_t size = 0;
  switch (network.derivation) {
    case DerivationStyle::NearSlip10:
      if (account != 0 || change != 0 || !near_derivation_path(address_index, local)) return false;
      size = 3;
      break;
    case DerivationStyle::StellarSep5:
      if (account != 0 || change != 0 || !stellar_derivation_path(address_index, local)) return false;
      size = 3;
      break;
    case DerivationStyle::AllHardenedBip44:
      if (network.encoding == AddressEncoding::Ed25519Blake2bBase58 && network.derivation_coin_type == 1729) {
        if (!tezos_derivation_path(account, change, address_index, local)) return false;
        size = 5;
        break;
      }
      if (network.encoding == AddressEncoding::Ed25519Base32 && network.derivation_coin_type == 283) {
        if (!algorand_derivation_path(account, change, address_index, local)) return false;
        size = 5;
        break;
      }
      local[size++] = 44 | kHardenedOffset;
      local[size++] = network.derivation_coin_type | kHardenedOffset;
      local[size++] = account | kHardenedOffset;
      local[size++] = change | kHardenedOffset;
      local[size++] = address_index | kHardenedOffset;
      break;
    case DerivationStyle::SolanaBip44:
      if (!solana_derivation_path(account, address_index, local)) return false;
      size = 5;
      break;
    case DerivationStyle::CardanoBip1852:
      local[size++] = 1852 | kHardenedOffset;
      local[size++] = network.derivation_coin_type | kHardenedOffset;
      local[size++] = account | kHardenedOffset;
      local[size++] = change;  // role: 0 payment, 2 stake
      local[size++] = address_index;
      break;
    default:
      return false;
  }
  for (size_t index = 0; index < size; ++index) path[index] = local[index];
  *out_size = size;
  return true;
}

WalletError derive_ed25519_address(const NetworkProfile &network,
                                   const uint8_t seed[kSeedSize],
                                   uint32_t account, uint32_t change,
                                   uint32_t address_index, DerivedAddress *out) {
  uint32_t path[6];
  size_t path_size = 0;
  uint8_t child[32];
  uint8_t public_key[32];
  if (network.derivation == DerivationStyle::CardanoBip1852) {
    const uint32_t payment_path[5] = {
        1852 | kHardenedOffset, network.derivation_coin_type | kHardenedOffset,
        account | kHardenedOffset, change, address_index};
    const uint32_t stake_path[5] = {
        1852 | kHardenedOffset, network.derivation_coin_type | kHardenedOffset,
        account | kHardenedOffset, 2, 0};
    CardanoKey payment = {};
    CardanoKey stake = {};
    if (!cardano_derive_path(seed, payment_path, 5, &payment) ||
        !cardano_derive_path(seed, stake_path, 5, &stake)) {
      secure_zero(&payment, sizeof(payment));
      secure_zero(&stake, sizeof(stake));
      return WalletError::CryptoFailure;
    }
    memcpy(out->private_key, payment.kL, kPrivateKeySize);
    const WalletError result =
        address_cardano_base(payment.public_key, stake.public_key,
                             out->address, sizeof(out->address));
    secure_zero(&payment, sizeof(payment));
    secure_zero(&stake, sizeof(stake));
    return result;
  }
  if (!build_slip10_path(network, account, change, address_index, path, &path_size)) {
    return WalletError::InvalidArgument;
  }
  if (!slip10_ed25519_derive(seed, kSeedSize, path, path_size, child)) {
    return WalletError::CryptoFailure;
  }
  memcpy(out->private_key, child, kPrivateKeySize);
  if (!(network.encoding == AddressEncoding::Nem
          ? nem_public_key(child, public_key)
          : ed25519_public_key(child, public_key))) {
    secure_zero(child, sizeof(child));
    return WalletError::CryptoFailure;
  }
  WalletError result = WalletError::Ok;
  switch (network.encoding) {
    case AddressEncoding::SiaV2:
      result = sia_address(public_key, out->address, sizeof(out->address));
      break;
    case AddressEncoding::Nem:
      result = nem_address(public_key, out->address, sizeof(out->address));
      break;
    case AddressEncoding::IcpLedgerAccount:
      result = icp_ledger_address(public_key, out->address, sizeof(out->address));
      break;
    case AddressEncoding::HederaKeyAlias:
      result = hedera_key_alias(public_key, out->address, sizeof(out->address))
          ? WalletError::Ok : WalletError::CryptoFailure;
      break;
    case AddressEncoding::SuiEd25519:
      result = sui_address(public_key, out->address, sizeof(out->address))
          ? WalletError::Ok : WalletError::CryptoFailure;
      break;
    case AddressEncoding::IcpPrincipal:
      result = address_icp(public_key, out->address, sizeof(out->address));
      break;
    case AddressEncoding::NearImplicit:
      result = near_implicit_address(public_key, out->address, sizeof(out->address))
          ? WalletError::Ok : WalletError::CryptoFailure;
      break;
    case AddressEncoding::StellarStrKey:
      result = stellar_address(public_key, out->address, sizeof(out->address))
          ? WalletError::Ok : WalletError::CryptoFailure;
      break;
    case AddressEncoding::Ed25519Base58:
      {
        size_t size = sizeof(out->address);
        result = address_solana(public_key, out->address, &size);
        break;
      }
    case AddressEncoding::Aeternity:
      result = address_aeternity(public_key, out->address,
                                 sizeof(out->address));
      break;
    case AddressEncoding::Ed25519Base32:
      result = address_algorand(public_key, out->address, sizeof(out->address));
      break;
    case AddressEncoding::Ed25519Blake2bBase58:
      {
        size_t size = sizeof(out->address);
        result = address_tezos_tz1(public_key, out->address, &size);
        break;
      }
    case AddressEncoding::Ss58Ed25519:
      result = address_ss58(network.account_version, public_key, out->address,
                            sizeof(out->address));
      break;
    case AddressEncoding::TonAddress:
      result = address_ton(public_key, network.ton_wallet_id, 0x51,
                           out->address, sizeof(out->address));
      break;
    case AddressEncoding::Ed25519Blake2b224Bech32:
      {
        // Cardano base address: payment role 0 and stake role 2.
        uint32_t stake_path[6];
        size_t stake_path_size = 0;
        uint8_t stake_child[32];
        uint8_t stake_key[32];
        if (!build_slip10_path(network, account, 2, address_index, stake_path,
                               &stake_path_size)
            || !slip10_ed25519_derive(seed, kSeedSize, stake_path, stake_path_size, stake_child) || !ed25519_public_key(stake_child, stake_key)) {
          secure_zero(stake_child, sizeof(stake_child));
          secure_zero(stake_key, sizeof(stake_key));
          secure_zero(child, sizeof(child));
          secure_zero(public_key, sizeof(public_key));
          return WalletError::CryptoFailure;
        }
        result = address_cardano_base(public_key, stake_key, out->address,
                                      sizeof(out->address));
        secure_zero(stake_child, sizeof(stake_child));
        secure_zero(stake_key, sizeof(stake_key));
        break;
      }
    default:
      result = WalletError::InvalidArgument;
      break;
  }
  secure_zero(child, sizeof(child));
  secure_zero(public_key, sizeof(public_key));
  return result;
}

}  // namespace

WalletError derive_address_ex(const HdPrivateNode &master, const uint8_t *seed,
                              const NetworkProfile &network,
                              uint32_t account, uint32_t change,
                              uint32_t address_index, QrlProgressHook progress,
                              void *context, DerivedAddress *out) {
  if (out == nullptr || account >= kHardenedOffset || change >= kHardenedOffset || address_index >= kHardenedOffset || network.bip_purpose >= kHardenedOffset || network.derivation_coin_type >= kHardenedOffset) {
    return WalletError::InvalidArgument;
  }
  memset(out, 0, sizeof(*out));
  out->network = &network;
  if (!build_path_text(network, account, change, address_index, out->path,
                       sizeof(out->path))) {
    clear_derived_address(out);
    return WalletError::BufferTooSmall;
  }

  // QRL derives an XMSS tree root straight from the BIP39 seed.  It has no
  // BIP32 path and its public key cannot be produced by the SE050.
  if (network.encoding == AddressEncoding::QrlXmss) {
    if (seed == nullptr || account != 0 || change != 0) {
      clear_derived_address(out);
      return WalletError::InvalidArgument;
    }
    uint8_t qrl_seed[kQrlSeedSize];
    WalletError result = qrl_seed_from_bip39(seed, address_index, qrl_seed);
    if (result == WalletError::Ok) {
      result = qrl_xmss_address_ex(qrl_seed, kQrlDefaultHeight, progress,
                                   context, out->address, sizeof(out->address));
    }
    secure_zero(qrl_seed, sizeof(qrl_seed));
    if (result != WalletError::Ok) clear_derived_address(out);
    return result;
  }

  // EIP-2333 networks derive straight from the BIP39 seed.
  if (network.encoding == AddressEncoding::Bech32mBlsChia) {
#if !defined(HEXWALLET_HOST_TEST)
    // Current BLS scalar multiplication uses variable-time MPI arithmetic.
    // Do not process a device secret until a reviewed constant-time backend exists.
    clear_derived_address(out);
    return WalletError::InvalidArgument;
#endif
    if (seed == nullptr) {
      clear_derived_address(out);
      return WalletError::InvalidArgument;
    }
    // The signing key must be the same EIP-2333 key the address hashes, so it
    // is derived here rather than by a separate code path.
    if (!chia_standard_private_key(seed, kSeedSize, address_index,
                                   out->private_key) ||
        !chia_standard_address(seed, kSeedSize, address_index, out->address,
                               sizeof(out->address))) {
      clear_derived_address(out);
      return WalletError::CryptoFailure;
    }
    return WalletError::Ok;
  }

  // Ed25519 networks use SLIP-0010 from the seed.
  if (network.encoding == AddressEncoding::Ed25519Base58 || network.encoding == AddressEncoding::Aeternity || network.encoding == AddressEncoding::Ed25519Base32 || network.encoding == AddressEncoding::Ed25519Blake2bBase58 || network.encoding == AddressEncoding::Ed25519Blake2b224Bech32 || network.encoding == AddressEncoding::StellarStrKey || network.encoding == AddressEncoding::NearImplicit || network.encoding == AddressEncoding::Ss58Ed25519 || network.encoding == AddressEncoding::TonAddress || network.encoding == AddressEncoding::SuiEd25519 || network.encoding == AddressEncoding::HederaKeyAlias || network.encoding == AddressEncoding::IcpPrincipal || network.encoding == AddressEncoding::SiaV2 || network.encoding == AddressEncoding::Nem || network.encoding == AddressEncoding::IcpLedgerAccount) {
    if (seed == nullptr) {
      clear_derived_address(out);
      return WalletError::InvalidArgument;
    }
    const WalletError result =
      derive_ed25519_address(network, seed, account, change, address_index, out);
    if (result != WalletError::Ok) clear_derived_address(out);
    return result;
  }

  // secp256k1 networks derive a BIP32 child.
  HdPrivateNode child;
  WalletError result = hd_private_derive_path(&master, out->path, &child);
  if (result != WalletError::Ok) {
    clear_derived_address(out);
    return result;
  }
  memcpy(out->private_key, child.private_key, kPrivateKeySize);

  if (network.encoding == AddressEncoding::CryptoNote) {
    const CryptoNoteAddressProfile profile = cryptonote_profile_for(network);
    result = cryptonote_address_from_seed_at(profile, child.private_key, account,
                                             address_index, out->address,
                                             sizeof(out->address),
                                             out->private_key);
  } else if (network.encoding == AddressEncoding::Evm || network.encoding == AddressEncoding::Tron ||
             network.encoding == AddressEncoding::VeChainAddress ||
             network.encoding == AddressEncoding::IconAddress ||
             network.encoding == AddressEncoding::Blake2bBase32Filecoin) {
    uint8_t public_key[kUncompressedPublicKeySize];
    result = uncompressed_public_key_from_private(child.private_key, public_key);
    if (result == WalletError::Ok && network.encoding == AddressEncoding::Evm) {
      result = address_evm(public_key, out->address, sizeof(out->address));
    } else if (result == WalletError::Ok && network.encoding == AddressEncoding::VeChainAddress) {
      result = address_vechain(public_key, out->address, sizeof(out->address));
    } else if (result == WalletError::Ok && network.encoding == AddressEncoding::IconAddress) {
      result = address_icon(public_key, out->address, sizeof(out->address));
    } else if (result == WalletError::Ok && network.encoding == AddressEncoding::Blake2bBase32Filecoin) {
      result = address_filecoin(public_key, out->address, sizeof(out->address));
    } else if (result == WalletError::Ok) {
      size_t output_size = sizeof(out->address);
      result = address_keccak_base58(network.account_version, public_key,
                                     out->address, &output_size);
    }
    secure_zero(public_key, sizeof(public_key));
  } else {
    uint8_t public_key[kCompressedPublicKeySize];
    result = public_key_from_private(child.private_key, public_key);
    if (result == WalletError::Ok) {
      switch (network.encoding) {
        case AddressEncoding::P2wpkh:
          result = address_p2wpkh(network.utxo, public_key, out->address,
                                  sizeof(out->address));
          break;
        case AddressEncoding::P2shP2wpkh:
          {
            size_t output_size = sizeof(out->address);
            result = address_p2sh_p2wpkh(network.utxo, public_key, out->address,
                                         &output_size);
            break;
          }
        case AddressEncoding::P2pkh:
          {
            size_t output_size = sizeof(out->address);
            result = address_p2pkh(network.utxo, public_key, out->address,
                                   &output_size);
            break;
          }
        case AddressEncoding::ZcashTransparent:
          {
            size_t output_size = sizeof(out->address);
            result = address_zcash_transparent(network.alt_p2pkh_version,
                                               network.alt_p2sh_version,
                                               public_key, out->address,
                                               &output_size);
            break;
          }
        case AddressEncoding::CashAddr:
          result = address_cashaddr(network.alt_hrp, public_key, out->address,
                                    sizeof(out->address));
          break;
        case AddressEncoding::Bech32Cosmos:
          result = address_cosmos_bech32(network.alt_hrp, public_key,
                                         out->address, sizeof(out->address));
          break;
        case AddressEncoding::Bech32Avalanche:
          result = address_avalanche_xp(network.alt_hrp, public_key,
                                        out->address, sizeof(out->address));
          break;
        case AddressEncoding::KaspaBech32:
          result = address_kaspa(public_key, out->address, sizeof(out->address));
          break;
        case AddressEncoding::Blake2bBase58Ergo:
          {
            size_t output_size = sizeof(out->address);
            result = address_ergo(public_key, out->address, &output_size);
            break;
          }
        case AddressEncoding::DecredAddress:
          {
            size_t output_size = sizeof(out->address);
            result = address_decred(network.alt_p2pkh_version, public_key,
                                    out->address, &output_size);
            break;
          }
        case AddressEncoding::CkbAddress:
          result = address_ckb(public_key, out->address,
                               sizeof(out->address));
          break;
        case AddressEncoding::GraphenePubkey:
          result = address_graphene("STM", public_key, out->address,
                                    sizeof(out->address));
          break;
        case AddressEncoding::Ripple:
          {
            size_t output_size = sizeof(out->address);
            result = address_ripple(public_key, out->address, &output_size);
            break;
          }
        default:
          result = WalletError::InvalidArgument;
          break;
      }
    }
    secure_zero(public_key, sizeof(public_key));
  }
  secure_zero(&child, sizeof(child));
  if (result != WalletError::Ok) clear_derived_address(out);
  return result;
}

void clear_derived_address(DerivedAddress *address) {
  if (address != nullptr) secure_zero(address, sizeof(*address));
}

WalletError derive_cryptonote_keys(const HdPrivateNode &master,
                                   const NetworkProfile &network,
                                   uint32_t account, uint32_t change,
                                   uint32_t address_index,
                                   uint8_t out_spend_key[kCryptoNoteKeySize],
                                   uint8_t out_view_key[kCryptoNoteKeySize]) {
  if (out_spend_key == nullptr || out_view_key == nullptr ||
      network.encoding != AddressEncoding::CryptoNote) {
    return WalletError::InvalidArgument;
  }
  char path[kDerivationPathTextSize];
  if (!build_path_text(network, account, change, address_index, path,
                       sizeof(path))) {
    return WalletError::InvalidArgument;
  }
  HdPrivateNode child;
  WalletError result = hd_private_derive_path(&master, path, &child);
  if (result == WalletError::Ok) {
    result = cryptonote_private_keys_from_seed(child.private_key,
                                               out_spend_key, out_view_key);
  }
  secure_zero(&child, sizeof(child));
  secure_zero(path, sizeof(path));
  if (result != WalletError::Ok) {
    secure_zero(out_spend_key, kCryptoNoteKeySize);
    secure_zero(out_view_key, kCryptoNoteKeySize);
  }
  return result;
}

WalletError derive_address(const HdPrivateNode &master, const uint8_t *seed,
                           const NetworkProfile &network,
                           uint32_t account, uint32_t change,
                           uint32_t address_index, DerivedAddress *out) {
  return derive_address_ex(master, seed, network, account, change, address_index,
                           nullptr, nullptr, out);
}

WalletError derive_cryptonote_subaddress(const HdPrivateNode &master,
                                         const NetworkProfile &network,
                                         uint32_t account, uint32_t change,
                                         uint32_t address_index,
                                         uint32_t subaddress_major,
                                         uint32_t subaddress_minor,
                                         DerivedAddress *out) {
  if (out == nullptr || network.encoding != AddressEncoding::CryptoNote) {
    return WalletError::InvalidArgument;
  }
  // Fill the path, the standard address and the master spend key first; (0, 0)
  // is exactly the standard address.
  WalletError result =
      derive_address(master, nullptr, network, account, change, address_index, out);
  if (result != WalletError::Ok || (subaddress_major == 0 && subaddress_minor == 0)) {
    return result;
  }

  uint8_t spend_key[kCryptoNoteKeySize];
  uint8_t view_key[kCryptoNoteKeySize];
  result = derive_cryptonote_keys(master, network, account, change,
                                  address_index, spend_key, view_key);
  if (result != WalletError::Ok) {
    clear_derived_address(out);
    return result;
  }

  const CryptoNoteAddressProfile profile = cryptonote_profile_for(network);
  if (profile.subaddress_prefix == 0) {
    clear_derived_address(out);
    return WalletError::InvalidArgument;
  }
  uint8_t sub_secret[kCryptoNoteKeySize];
  uint8_t sub_public[kCryptoNoteKeySize];
  uint8_t sub_view[kCryptoNoteKeySize];
  result = cryptonote_subaddress_keys(spend_key, view_key, subaddress_major,
                                      subaddress_minor, sub_secret, sub_public,
                                      sub_view);
  if (result == WalletError::Ok) {
    result = cryptonote_address_from_public_keys(profile.subaddress_prefix,
                                                 sub_public, sub_view,
                                                 out->address,
                                                 sizeof(out->address));
  }
  if (result == WalletError::Ok) {
    // Signing re-derives this scalar per input, but reporting it keeps the
    // "address and key agree" invariant visible to callers.
    memcpy(out->private_key, sub_secret, kCryptoNoteKeySize);
    const size_t used = strlen(out->path);
    if (used < sizeof(out->path)) {
      snprintf(out->path + used, sizeof(out->path) - used, "+%lu/%lu",
               static_cast<unsigned long>(subaddress_major),
               static_cast<unsigned long>(subaddress_minor));
    }
  } else {
    clear_derived_address(out);
  }
  secure_zero(spend_key, sizeof(spend_key));
  secure_zero(view_key, sizeof(view_key));
  secure_zero(sub_secret, sizeof(sub_secret));
  secure_zero(sub_public, sizeof(sub_public));
  secure_zero(sub_view, sizeof(sub_view));
  return result;
}

bool run_address_self_tests() {
  static const uint8_t kPrivateOne[kPrivateKeySize] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    1,
  };
  static const uint8_t kExpectedCompressed[kCompressedPublicKeySize] = {
    0x02,
    0x79,
    0xbe,
    0x66,
    0x7e,
    0xf9,
    0xdc,
    0xbb,
    0xac,
    0x55,
    0xa0,
    0x62,
    0x95,
    0xce,
    0x87,
    0x0b,
    0x07,
    0x02,
    0x9b,
    0xfc,
    0xdb,
    0x2d,
    0xce,
    0x28,
    0xd9,
    0x59,
    0xf2,
    0x81,
    0x5b,
    0x16,
    0xf8,
    0x17,
    0x98,
  };
  uint8_t compressed[kCompressedPublicKeySize];
  uint8_t uncompressed[kUncompressedPublicKeySize];
  char address[kAddressTextSize];
  size_t address_size = sizeof(address);
  bool passed = public_key_from_private(kPrivateOne, compressed) == WalletError::Ok && crypto_constant_time_equal(compressed, kExpectedCompressed, sizeof(compressed)) && address_p2pkh(kBitcoinMainnet, compressed, address, &address_size) == WalletError::Ok && strcmp(address, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH") == 0;
  passed = passed && uncompressed_public_key_from_private(kPrivateOne, uncompressed) == WalletError::Ok && address_evm(uncompressed, address, sizeof(address)) == WalletError::Ok && strcmp(address, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf") == 0;
  // Official Conflux Ledger app vector: m/44'/503'/0'/0/0 public key.
  static const uint8_t kConfluxPublic[kUncompressedPublicKeySize] = {
    0x04, 0x4b, 0x0e, 0x7a, 0xa1, 0x24, 0x22, 0xc8, 0xbd, 0x4b, 0x2b, 0xed,
    0x18, 0xbb, 0xa7, 0x75, 0xe0, 0x27, 0x1e, 0x6b, 0x9a, 0x99, 0xa1, 0xbf,
    0x53, 0x40, 0x57, 0x2a, 0xce, 0xeb, 0x80, 0xe0, 0x35, 0x05, 0x88, 0xd6,
    0xdc, 0xc8, 0x97, 0x07, 0x41, 0x2b, 0x12, 0x76, 0xe4, 0xcd, 0xfb, 0xc5,
    0xfc, 0x65, 0x91, 0x06, 0x96, 0xc6, 0x89, 0x46, 0x56, 0x11, 0xb1, 0x2d,
    0xda, 0x5b, 0x07, 0x00, 0xdb,
  };
  passed = passed && address_evm(kConfluxPublic, address, sizeof(address)) == WalletError::Ok && strcmp(address, "0xdc2a4fe87a86f8cd561fdd56d26075b4496fc831") == 0;
  passed = passed && run_alt_address_self_tests();

  // CryptoNote subaddress derivation must be deterministic, must differ from
  // the standard address, and (0, 0) must be byte-identical to it.
  {
    uint8_t seed[kSeedSize];
    for (size_t index = 0; index < sizeof(seed); ++index)
      seed[index] = static_cast<uint8_t>(index * 7 + 3);
    const NetworkProfile *network = find_network_profile("xmr");
    HdPrivateNode master = {};
    DerivedAddress standard = {};
    DerivedAddress zero = {};
    DerivedAddress sub = {};
    bool ok = network != nullptr &&
              hd_private_from_seed(seed, sizeof(seed), &master) == WalletError::Ok &&
              derive_address(master, nullptr, *network, 0, 0, 0, &standard) ==
                  WalletError::Ok &&
              derive_cryptonote_subaddress(master, *network, 0, 0, 0, 0, 0,
                                           &zero) == WalletError::Ok &&
              derive_cryptonote_subaddress(master, *network, 0, 0, 0, 0, 1,
                                           &sub) == WalletError::Ok;
    ok = ok && strcmp(standard.address, zero.address) == 0 &&
         strcmp(standard.path, zero.path) == 0 &&
         strcmp(standard.address, sub.address) != 0 &&
         strstr(sub.path, "+0/1") != nullptr &&
         !crypto_constant_time_equal(standard.private_key, sub.private_key,
                                     kPrivateKeySize);
    // Repeating the derivation must produce the same address (no hidden state).
    DerivedAddress again = {};
    ok = ok && derive_cryptonote_subaddress(master, *network, 0, 0, 0, 0, 1,
                                            &again) == WalletError::Ok &&
         strcmp(sub.address, again.address) == 0;
    // Non-CryptoNote networks refuse subaddress indices instead of guessing.
    const NetworkProfile *bitcoin = find_network_profile("btc");
    ok = ok && bitcoin != nullptr &&
         derive_cryptonote_subaddress(master, *bitcoin, 0, 0, 0, 0, 1,
                                      &again) == WalletError::InvalidArgument;
    clear_derived_address(&standard);
    clear_derived_address(&zero);
    clear_derived_address(&sub);
    clear_derived_address(&again);
    secure_zero(&master, sizeof(master));
    secure_zero(seed, sizeof(seed));
    passed = passed && ok;
  }

  // New address-only profiles must derive a well-formed address from the same
  // seed path machinery; this is the bridge between the table and the encoder.
  {
    uint8_t seed[kSeedSize];
    for (size_t index = 0; index < sizeof(seed); ++index)
      seed[index] = static_cast<uint8_t>(index * 5 + 11);
    HdPrivateNode master = {};
    DerivedAddress derived = {};
    const NetworkProfile *aeternity = find_network_profile("ae");
    const NetworkProfile *ryo = find_network_profile("ryo");
    const NetworkProfile *zano = find_network_profile("zano");
    bool ok = aeternity != nullptr && ryo != nullptr && zano != nullptr &&
              hd_private_from_seed(seed, sizeof(seed), &master) == WalletError::Ok;
    ok = ok && derive_address(master, seed, *aeternity, 0, 0, 0, &derived) ==
                   WalletError::Ok &&
         strncmp(derived.address, "ak_", 3) == 0;
    ok = ok && derive_address(master, seed, *ryo, 0, 0, 0, &derived) ==
                   WalletError::Ok &&
         strncmp(derived.address, "RYoL", 4) == 0;
    ok = ok && derive_address(master, seed, *zano, 0, 0, 0, &derived) ==
                   WalletError::Ok &&
         strncmp(derived.address, "Zx", 2) == 0;
    // Zano publishes no standard subaddress prefix. Refuse, do not guess.
    ok = ok && derive_cryptonote_subaddress(master, *zano, 0, 0, 0, 0, 1,
                                            &derived) ==
                   WalletError::InvalidArgument;
    clear_derived_address(&derived);
    secure_zero(&master, sizeof(master));
    secure_zero(seed, sizeof(seed));
    passed = passed && ok;
  }

  secure_zero(compressed, sizeof(compressed));
  secure_zero(uncompressed, sizeof(uncompressed));
  secure_zero(address, sizeof(address));
  return passed;
}

}  // namespace hexwallet
