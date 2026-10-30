#include "WalletTransportPolicy.h"

#include "WalletConfig.h"

namespace hexwallet {

bool wallet_transport_allows(WalletTransport transport,
                             WalletTransportOperation operation,
                             const WalletTransportState &state) {
  if (transport == WalletTransport::Wifi) return false;
  const bool serial = transport == WalletTransport::SerialUsb;
  const bool paired_link = transport == WalletTransport::Nfc ||
                           transport == WalletTransport::BluetoothLowEnergy;
  if (!serial && !paired_link) return false;
  switch (operation) {
    case WalletTransportOperation::PublicCatalog:
    case WalletTransportOperation::PublicPrice:
    case WalletTransportOperation::PublicBlockHeight:
      return true;
    case WalletTransportOperation::SigningRequest:
    case WalletTransportOperation::ApprovalResponse:
      return state.authenticated && state.trusted_display && (serial || state.paired);
    case WalletTransportOperation::SecretExport:
      return false;
  }
  return false;
}
bool run_transport_policy_self_test() {
  const WalletTransportState trusted = { true, true, true };
  const WalletTransportState unpaired = { true, false, true };
  const WalletTransportState unauthenticated = { false, true, true };
  return !wallet_transport_allows(WalletTransport::Wifi,
                                 WalletTransportOperation::PublicPrice, trusted)
         && !wallet_transport_allows(WalletTransport::Wifi,
                                    WalletTransportOperation::PublicBlockHeight, trusted)
         && !wallet_transport_allows(WalletTransport::Wifi,
                                     WalletTransportOperation::SigningRequest, trusted)
         && !wallet_transport_allows(WalletTransport::Wifi,
                                     WalletTransportOperation::ApprovalResponse, trusted)
         && !wallet_transport_allows(WalletTransport::Wifi,
                                     WalletTransportOperation::SecretExport, trusted)
         && wallet_transport_allows(WalletTransport::BluetoothLowEnergy,
                                    WalletTransportOperation::SigningRequest, trusted)
         && wallet_transport_allows(WalletTransport::BluetoothLowEnergy,
                                    WalletTransportOperation::ApprovalResponse, trusted)
         && !wallet_transport_allows(WalletTransport::BluetoothLowEnergy,
                                     WalletTransportOperation::SigningRequest, unpaired)
         && !wallet_transport_allows(WalletTransport::BluetoothLowEnergy,
                                     WalletTransportOperation::SecretExport, trusted)
         && !wallet_transport_allows(WalletTransport::SerialUsb,
                                     WalletTransportOperation::SigningRequest, unauthenticated)
         && wallet_transport_allows(WalletTransport::Nfc,
                                    WalletTransportOperation::SigningRequest, trusted)
         && !wallet_transport_allows(WalletTransport::Nfc,
                                     WalletTransportOperation::SigningRequest, unpaired)
         && !wallet_transport_allows(WalletTransport::Nfc,
                                     WalletTransportOperation::SigningRequest, unauthenticated)
         && !wallet_transport_allows(WalletTransport::Nfc,
                                     WalletTransportOperation::SecretExport, trusted);
}

}  // namespace hexwallet
