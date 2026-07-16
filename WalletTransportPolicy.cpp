#include "WalletTransportPolicy.h"

#include "WalletConfig.h"

namespace hexwallet {

bool wallet_transport_allows(WalletTransport transport,
                             WalletTransportOperation operation,
                             const WalletTransportState &state) {
  switch (transport) {
    case WalletTransport::Wifi:
      return operation == WalletTransportOperation::PublicPrice ||
             operation == WalletTransportOperation::PublicBlockHeight;
    case WalletTransport::BluetoothLowEnergy:
      switch (operation) {
        case WalletTransportOperation::PublicCatalog:
        case WalletTransportOperation::PublicPrice:
        case WalletTransportOperation::PublicBlockHeight:
          return true;
        case WalletTransportOperation::SigningRequest:
        case WalletTransportOperation::ApprovalResponse:
          return state.authenticated && state.paired && state.trusted_display;
        case WalletTransportOperation::SecretExport:
          return false;
      }
      return false;
    case WalletTransport::SerialUsb:
      switch (operation) {
        case WalletTransportOperation::PublicCatalog:
        case WalletTransportOperation::PublicPrice:
        case WalletTransportOperation::PublicBlockHeight:
          return true;
        case WalletTransportOperation::SigningRequest:
        case WalletTransportOperation::ApprovalResponse:
          return state.authenticated &&
                 (state.trusted_display || HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION != 0);
        case WalletTransportOperation::SecretExport:
          return state.authenticated && HEXWALLET_ENABLE_SECRET_EXPORT != 0;
      }
      return false;
  }
  return false;
}

bool run_transport_policy_self_test() {
  const WalletTransportState trusted = {true, true, true};
  const WalletTransportState unpaired = {true, false, true};
  const WalletTransportState unauthenticated = {false, true, true};
  return wallet_transport_allows(WalletTransport::Wifi,
                                 WalletTransportOperation::PublicPrice, trusted) &&
         wallet_transport_allows(WalletTransport::Wifi,
                                 WalletTransportOperation::PublicBlockHeight, trusted) &&
         !wallet_transport_allows(WalletTransport::Wifi,
                                  WalletTransportOperation::SigningRequest, trusted) &&
         !wallet_transport_allows(WalletTransport::Wifi,
                                  WalletTransportOperation::ApprovalResponse, trusted) &&
         !wallet_transport_allows(WalletTransport::Wifi,
                                  WalletTransportOperation::SecretExport, trusted) &&
         wallet_transport_allows(WalletTransport::BluetoothLowEnergy,
                                 WalletTransportOperation::SigningRequest, trusted) &&
         wallet_transport_allows(WalletTransport::BluetoothLowEnergy,
                                 WalletTransportOperation::ApprovalResponse, trusted) &&
         !wallet_transport_allows(WalletTransport::BluetoothLowEnergy,
                                  WalletTransportOperation::SigningRequest, unpaired) &&
         !wallet_transport_allows(WalletTransport::BluetoothLowEnergy,
                                  WalletTransportOperation::SecretExport, trusted) &&
         !wallet_transport_allows(WalletTransport::SerialUsb,
                                  WalletTransportOperation::SigningRequest, unauthenticated);
}

}  // namespace hexwallet
