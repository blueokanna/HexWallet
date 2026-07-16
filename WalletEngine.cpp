#include "WalletEngine.h"

#include <stdio.h>
#include <string.h>

#include "CryptoPrimitives.h"
#include "CryptoNoteAddress.h"
#include "WalletAddresses.h"

namespace hexwallet {

static_assert(kAddressTextSize >= kCryptoNoteStandardAddressSize,
              "DerivedAddress must hold a CryptoNote standard address");

WalletError derive_address(const HdPrivateNode &master, const NetworkProfile &network,
                           uint32_t account, uint32_t change, uint32_t address_index,
                           DerivedAddress *out) {
  if (out == nullptr || account >= kHardenedOffset || change >= kHardenedOffset ||
      address_index >= kHardenedOffset || network.bip_purpose >= kHardenedOffset ||
      network.derivation_coin_type >= kHardenedOffset) {
    return WalletError::InvalidArgument;
  }
  memset(out, 0, sizeof(*out));
  out->network = &network;
  const int written = snprintf(out->path, sizeof(out->path), "m/%lu'/%lu'/%lu'/%lu/%lu",
                               static_cast<unsigned long>(network.bip_purpose),
                               static_cast<unsigned long>(network.derivation_coin_type),
                               static_cast<unsigned long>(account),
                               static_cast<unsigned long>(change),
                               static_cast<unsigned long>(address_index));
  if (written <= 0 || static_cast<size_t>(written) >= sizeof(out->path)) {
    clear_derived_address(out);
    return WalletError::BufferTooSmall;
  }
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
  } else if (network.encoding == AddressEncoding::Evm || network.encoding == AddressEncoding::Tron) {
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
    if (result == WalletError::Ok && network.encoding == AddressEncoding::P2wpkh) {
      result = address_p2wpkh(network.utxo, public_key, out->address, sizeof(out->address));
    } else if (result == WalletError::Ok && network.encoding == AddressEncoding::P2shP2wpkh) {
      size_t output_size = sizeof(out->address);
      result = address_p2sh_p2wpkh(network.utxo, public_key, out->address, &output_size);
    } else if (result == WalletError::Ok) {
      size_t output_size = sizeof(out->address);
      result = address_p2pkh(network.utxo, public_key, out->address, &output_size);
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
  secure_zero(compressed, sizeof(compressed));
  secure_zero(uncompressed, sizeof(uncompressed));
  secure_zero(address, sizeof(address));
  return passed;
}

}  // namespace hexwallet
