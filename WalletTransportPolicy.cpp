#include "WalletTransportPolicy.h"

#include "WalletConfig.h"

namespace hexwallet
{

  bool wallet_transport_allows(WalletTransport transport,
                               WalletTransportOperation operation,
                               const WalletTransportState &state)
  {
    if (transport == WalletTransport::Wifi)
      return false;
    const bool serial = transport == WalletTransport::SerialUsb;
    const bool paired_link = transport == WalletTransport::Nfc ||
                             transport == WalletTransport::BluetoothLowEnergy;
    if (!serial && !paired_link)
      return false;
    const bool host_only_confirmation =
        serial && HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION != 0;
    const bool review_surface = state.trusted_display || host_only_confirmation;
    switch (operation)
    {
    case WalletTransportOperation::PublicCatalog:
    case WalletTransportOperation::PublicPrice:
    case WalletTransportOperation::PublicBlockHeight:
      return true;
    case WalletTransportOperation::SigningRequest:
    case WalletTransportOperation::ApprovalResponse:
      return state.authenticated && review_surface && !state.battery_critical &&
             (serial || state.paired);
    case WalletTransportOperation::SecretExport:
      return false;
    }
    return false;
  }
  bool run_transport_policy_self_test()
  {
    const WalletTransportState trusted = {true, true, true, false};
    const WalletTransportState unpaired = {true, false, true, false};
    const WalletTransportState unauthenticated = {false, true, true, false};
    const WalletTransportState headless = {true, false, false, false};
    const WalletTransportState paired_headless = {true, true, false, false};
    const WalletTransportState critical_serial = {true, false, true, true};
    const WalletTransportState critical_link = {true, true, true, true};
    const bool battery_bits =
        !wallet_transport_allows(WalletTransport::SerialUsb,
                                 WalletTransportOperation::SigningRequest, critical_serial) &&
        !wallet_transport_allows(WalletTransport::SerialUsb,
                                 WalletTransportOperation::ApprovalResponse, critical_serial) &&
        !wallet_transport_allows(WalletTransport::Nfc,
                                 WalletTransportOperation::SigningRequest, critical_link) &&
        !wallet_transport_allows(WalletTransport::BluetoothLowEnergy,
                                 WalletTransportOperation::ApprovalResponse, critical_link) &&
        wallet_transport_allows(WalletTransport::SerialUsb,
                                WalletTransportOperation::PublicCatalog, critical_serial);
    const bool host_only = HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION != 0;
    const bool host_only_bits =
        wallet_transport_allows(WalletTransport::SerialUsb,
                                WalletTransportOperation::ApprovalResponse,
                                headless) == host_only &&
        wallet_transport_allows(WalletTransport::SerialUsb,
                                WalletTransportOperation::SigningRequest,
                                headless) == host_only &&
        !wallet_transport_allows(WalletTransport::Nfc,
                                 WalletTransportOperation::ApprovalResponse,
                                 paired_headless) &&
        !wallet_transport_allows(WalletTransport::BluetoothLowEnergy,
                                 WalletTransportOperation::SigningRequest,
                                 paired_headless);
    return host_only_bits && battery_bits &&
           !wallet_transport_allows(WalletTransport::Wifi,
                                    WalletTransportOperation::PublicPrice, trusted) &&
           !wallet_transport_allows(WalletTransport::Wifi,
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
                                    WalletTransportOperation::SigningRequest, unauthenticated) &&
           wallet_transport_allows(WalletTransport::Nfc,
                                   WalletTransportOperation::SigningRequest, trusted) &&
           !wallet_transport_allows(WalletTransport::Nfc,
                                    WalletTransportOperation::SigningRequest, unpaired) &&
           !wallet_transport_allows(WalletTransport::Nfc,
                                    WalletTransportOperation::SigningRequest, unauthenticated) &&
           !wallet_transport_allows(WalletTransport::Nfc,
                                    WalletTransportOperation::SecretExport, trusted);
  }

}
