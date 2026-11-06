#ifndef HEXWALLET_TRANSPORT_POLICY_H
#define HEXWALLET_TRANSPORT_POLICY_H

#include <stdint.h>

namespace hexwallet {

enum class WalletTransport : uint8_t {
  SerialUsb,
  Nfc,
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
  // Set when the battery monitor reports a critical pack. A signing burst pulls
  // more current than idle, and a brown-out in the middle of a signature is worse
  // than refusing the request, so the policy closes the signing surface instead
  // of leaving it to each adapter to remember.
  bool battery_critical;
};

bool wallet_transport_allows(WalletTransport transport,
                             WalletTransportOperation operation,
                             const WalletTransportState &state);
bool run_transport_policy_self_test();

}  // namespace hexwallet

#endif
