#ifndef HEXWALLET_TRANSPORT_POLICY_H
#define HEXWALLET_TRANSPORT_POLICY_H

#include <stdint.h>

namespace hexwallet {

enum class WalletTransport : uint8_t {
  SerialUsb,
  BluetoothLowEnergy,
  Wifi,
};

enum class WalletTransportOperation : uint8_t {
  PublicCatalog,
  PublicPrice,
  PublicBlockHeight,
  SigningRequest,
  ApprovalResponse,
  SecretExport,
};

struct WalletTransportState {
  bool authenticated;
  bool paired;
  bool trusted_display;
};

bool wallet_transport_allows(WalletTransport transport,
                             WalletTransportOperation operation,
                             const WalletTransportState &state);
bool run_transport_policy_self_test();

}  // namespace hexwallet

#endif
