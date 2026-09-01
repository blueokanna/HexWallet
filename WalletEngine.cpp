#include "WalletEngine.h"

#include <stdio.h>
#include <string.h>

#include "CryptoExtended.h"
#include "CryptoNoteAddress.h"
#include "CryptoPrimitives.h"
#include "WalletAddresses.h"
#include "WalletAltAddresses.h"

namespace hexwallet {

static_assert(kAddressTextSize >= kCryptoNoteStandardAddressSize,
              "DerivedAddress must hold a CryptoNote standard address");

namespace {

// Build the display derivation path for a network style.
bool build_path_text(const NetworkProfile &network, uint32_t account,
                     uint32_t change, uint32_t address_index, char *path,
                     size_t path_size) {
  int written = 0;
  switch (network.derivation) {
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
      written = snprintf(path, path_size, "m/1852'/%lu'/%lu'/0'/%lu'",
                         static_cast<unsigned long>(network.derivation_coin_type),
                         static_cast<unsigned long>(account),
                         static_cast<unsigned long>(address_index));
      break;
    case DerivationStyle::ChiaEip2333:
      written = snprintf(path, path_size, "m/12381'/%lu'/0'/%lu'",
                         static_cast<unsigned long>(network.derivation_coin_type),
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
    case DerivationStyle::AllHardenedBip44:
      local[size++] = 44 | kHardenedOffset;
      local[size++] = network.derivation_coin_type | kHardenedOffset;
      local[size++] = account | kHardenedOffset;
      local[size++] = change | kHardenedOffset;
      local[size++] = address_index | kHardenedOffset;
      break;
    case DerivationStyle::SolanaBip44:
      local[size++] = 44 | kHardenedOffset;
      local[size++] = network.derivation_coin_type | kHardenedOffset;
      local[size++] = account | kHardenedOffset;
      local[size++] = 0 | kHardenedOffset;
      local[size++] = address_index | kHardenedOffset;
      break;
    case DerivationStyle::CardanoBip1852:
      local[size++] = 1852 | kHardenedOffset;
      local[size++] = network.derivation_coin_type | kHardenedOffset;
      local[size++] = account | kHardenedOffset;
      local[size++] = change | kHardenedOffset;  // role: 0 payment, 2 stake
      local[size++] = address_index | kHardenedOffset;
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
  if (!build_slip10_path(network, account, change, address_index, path, &path_size)) {
    return WalletError::InvalidArgument;
  }
  if (!slip10_ed25519_derive(seed, kSeedSize, path, path_size, child)) {
    return WalletError::CryptoFailure;
  }
  memcpy(out->private_key, child, kPrivateKeySize);
  if (!ed25519_public_key(child, public_key)) {
    secure_zero(child, sizeof(child));
    return WalletError::CryptoFailure;
  }
  WalletError result = WalletError::Ok;
  switch (network.encoding) {
    case AddressEncoding::Ed25519Base58: {
      size_t size = sizeof(out->address);
      result = address_solana(public_key, out->address, &size);
      break;
    }
    case AddressEncoding::Ed25519Base32:
      result = address_algorand(public_key, out->address, sizeof(out->address));
      break;
    case AddressEncoding::Ed25519Blake2bBase58: {
      size_t size = sizeof(out->address);
      result = address_tezos_tz1(public_key, out->address, &size);
      break;
    }
    case AddressEncoding::QubicBase26:
      result = address_qubic(public_key, out->address, sizeof(out->address));
      break;
    case AddressEncoding::Ed25519Blake2b224Bech32: {
      // Cardano base address: payment role 0 and stake role 2.
      uint32_t stake_path[6];
      size_t stake_path_size = 0;
      uint8_t stake_child[32];
      uint8_t stake_key[32];
      if (!build_slip10_path(network, account, 2, address_index, stake_path,
                             &stake_path_size) ||
          !slip10_ed25519_derive(seed, kSeedSize, stake_path, stake_path_size, stake_child) ||
          !ed25519_public_key(stake_child, stake_key)) {
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

WalletError derive_address(const HdPrivateNode &master, const uint8_t *seed,
                           const NetworkProfile &network,
                           uint32_t account, uint32_t change,
                           uint32_t address_index, DerivedAddress *out) {
  if (out == nullptr || account >= kHardenedOffset || change >= kHardenedOffset ||
      address_index >= kHardenedOffset || network.bip_purpose >= kHardenedOffset ||
      network.derivation_coin_type >= kHardenedOffset) {
    return WalletError::InvalidArgument;
  }
  memset(out, 0, sizeof(*out));
  out->network = &network;
  if (!build_path_text(network, account, change, address_index, out->path,
                       sizeof(out->path))) {
    clear_derived_address(out);
    return WalletError::BufferTooSmall;
  }

  // EIP-2333 networks derive straight from the BIP39 seed.
  if (network.encoding == AddressEncoding::Bech32mBlsChia) {
    if (seed == nullptr) {
      clear_derived_address(out);
      return WalletError::InvalidArgument;
    }
    const WalletError result =
        chia_standard_address(seed, kSeedSize, address_index, out->address,
                              sizeof(out->address))
            ? WalletError::Ok
            : WalletError::CryptoFailure;
    if (result != WalletError::Ok) clear_derived_address(out);
    return result;
  }

  // Ed25519 networks use SLIP-0010 from the seed.
  if (network.encoding == AddressEncoding::Ed25519Base58 ||
      network.encoding == AddressEncoding::Ed25519Base32 ||
      network.encoding == AddressEncoding::Ed25519Blake2bBase58 ||
      network.encoding == AddressEncoding::Ed25519Blake2b224Bech32 ||
      network.encoding == AddressEncoding::QubicBase26) {
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
    const CryptoNoteAddressProfile profile = {network.account_version};
    result = cryptonote_address_from_seed(profile, child.private_key, out->address,
                                          sizeof(out->address), out->private_key);
  } else if (network.encoding == AddressEncoding::Evm ||
             network.encoding == AddressEncoding::Tron) {
    uint8_t public_key[kUncompressedPublicKeySize];
    result = uncompressed_public_key_from_private(child.private_key, public_key);
    if (result == WalletError::Ok && network.encoding == AddressEncoding::Evm) {
      result = address_evm(public_key, out->address, sizeof(out->address));
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
        case AddressEncoding::P2shP2wpkh: {
          size_t output_size = sizeof(out->address);
          result = address_p2sh_p2wpkh(network.utxo, public_key, out->address,
                                       &output_size);
          break;
        }
        case AddressEncoding::P2pkh: {
          size_t output_size = sizeof(out->address);
          result = address_p2pkh(network.utxo, public_key, out->address,
                                 &output_size);
          break;
        }
        case AddressEncoding::ZcashTransparent: {
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
        case AddressEncoding::Blake2bBase32Filecoin:
          result = address_filecoin(public_key, out->address, sizeof(out->address));
          break;
        case AddressEncoding::Blake2bBase58Ergo: {
          size_t output_size = sizeof(out->address);
          result = address_ergo(public_key, out->address, &output_size);
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

bool run_address_self_tests() {
  static const uint8_t kPrivateOne[kPrivateKeySize] = {
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
  };
  static const uint8_t kExpectedCompressed[kCompressedPublicKeySize] = {
      0x02,0x79,0xbe,0x66,0x7e,0xf9,0xdc,0xbb,0xac,0x55,0xa0,0x62,0x95,0xce,0x87,0x0b,
      0x07,0x02,0x9b,0xfc,0xdb,0x2d,0xce,0x28,0xd9,0x59,0xf2,0x81,0x5b,0x16,0xf8,0x17,0x98,
  };
  uint8_t compressed[kCompressedPublicKeySize];
  uint8_t uncompressed[kUncompressedPublicKeySize];
  char address[kAddressTextSize];
  size_t address_size = sizeof(address);
  bool passed = public_key_from_private(kPrivateOne, compressed) == WalletError::Ok &&
                crypto_constant_time_equal(compressed, kExpectedCompressed, sizeof(compressed)) &&
                address_p2pkh(kBitcoinMainnet, compressed, address, &address_size) == WalletError::Ok &&
                strcmp(address, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH") == 0;
  passed = passed && uncompressed_public_key_from_private(kPrivateOne, uncompressed) == WalletError::Ok &&
           address_evm(uncompressed, address, sizeof(address)) == WalletError::Ok &&
           strcmp(address, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf") == 0;
  passed = passed && run_alt_address_self_tests();
  secure_zero(compressed, sizeof(compressed));
  secure_zero(uncompressed, sizeof(uncompressed));
  secure_zero(address, sizeof(address));
  return passed;
}

}  // namespace hexwallet
