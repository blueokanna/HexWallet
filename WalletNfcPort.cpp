// NXP PN7160/PN7161 (NCI 2.0) NFC controller port.
//
// The wallet acts as an ISO-DEP *listening* target (card emulation); the phone
// is the reader/poller. Link frames arrive as APDUs and are handed to
// WalletNfcApdu, which forwards them to WalletLinkDevice.
//
// Scope and honesty:
//   * This file implements the NCI control sequence the wallet needs
//     (CORE_RESET, CORE_INIT, RF_DISCOVER_MAP, RF_DISCOVER listen) and the
//     DATA packet pump, using the NCI 1.0/2.0 encodings PN71xx speaks.
//   * The pin map is board specific and deliberately NOT defined anywhere in
//     this repository. Without HEXWALLET_NFC_PN7161 and the HEXWALLET_NFC_PIN_*
//     macros the port reports NotConfigured and NFC stays disabled instead of
//     driving an unrelated peripheral.
//   * Modules whose NFCC firmware must be patched at boot need that patch
//     step (vendor loader) before this port can talk NCI. A module that ships
//     with firmware already flashed works directly.
//   * The sequence has not yet been validated against a PN7161 EVK. Do not
//     claim NFC is production ready until it passes a reader-side conformance
//     run.
#include "WalletNfcPort.h"

#include <Arduino.h>
#include <SPI.h>
#include <string.h>

#include "WalletBoardPins.h"
#include "WalletSecurity.h"

namespace hexwallet
{
  namespace
  {

#if defined(HEXWALLET_NFC_PN7161) && defined(HEXWALLET_NFC_PIN_SCK) &&    \
    defined(HEXWALLET_NFC_PIN_MOSI) && defined(HEXWALLET_NFC_PIN_MISO) && \
    defined(HEXWALLET_NFC_PIN_CS) && defined(HEXWALLET_NFC_PIN_IRQ) &&    \
    defined(HEXWALLET_NFC_PIN_VEN)
#define HEXWALLET_NFC_PORT_AVAILABLE 1
#else
#define HEXWALLET_NFC_PORT_AVAILABLE 0
#endif

    constexpr size_t kNciMaxPayload = 255;
    constexpr size_t kNciMaxPacket = kNciMaxPayload + 3;
    constexpr uint32_t kNciResponseTimeoutMs = 250UL;
    constexpr uint32_t kNciResetTimeoutMs = 800UL;
    constexpr size_t kMaxApduChunk = 240;
    constexpr size_t kMaxApduSize = 1024;

    enum NciMessageType : uint8_t
    {
      kDataPacket = 0x00,
      kCommandPacket = 0x20,
      kResponsePacket = 0x40,
      kNotificationPacket = 0x60,
    };

    constexpr uint8_t kGidCore = 0x00;
    constexpr uint8_t kGidRf = 0x01;

    constexpr uint8_t kCoreResetOid = 0x00;
    constexpr uint8_t kCoreInitOid = 0x01;
    constexpr uint8_t kRfDiscoverMapOid = 0x00;
    constexpr uint8_t kRfDiscoverOid = 0x03;
    constexpr uint8_t kRfIntfActivatedOid = 0x05;
    constexpr uint8_t kRfDeactivateOid = 0x06;

    // NCI RF technology/mode and RF interface identifiers are separate fields.
    constexpr uint8_t kRfNfcAPassiveListen = 0x80;
    constexpr uint8_t kRfInterfaceIsoDep = 0x02;
    constexpr uint8_t kRfProtocolIsoDep = 0x04;
    constexpr uint8_t kRfDiscoveryFrequency = 0x01;

#if HEXWALLET_NFC_PORT_AVAILABLE

    SPIClass nfc_spi(HSPI);
    NfcPortState state = NfcPortState::InitFailed;
    NfcApduHandler apdu_handler = nullptr;
    NfcSessionLostHandler session_lost = nullptr;
    uint8_t tx_buffer[kMaxApduSize];
    size_t tx_size = 0, tx_offset = 0;
    uint8_t tx_limit = 0, tx_credits = 0;
    uint32_t transfer_started = 0;

    void clear_session()
    {
      secure_zero(tx_buffer, sizeof(tx_buffer));
      tx_size = tx_offset = 0;
      tx_limit = tx_credits = 0;
      if (session_lost != nullptr) session_lost();
    }
    bool bus_ready = false;
    uint8_t connection_id = 0;
    uint8_t apdu_buffer[kMaxApduSize];
    size_t apdu_size = 0;
    bool apdu_chained = false;
    uint32_t last_poll_ms = 0;

    void chip_select(bool selected)
    {
      digitalWrite(HEXWALLET_NFC_PIN_CS, selected ? LOW : HIGH);
    }

    bool irq_asserted()
    {
      return digitalRead(HEXWALLET_NFC_PIN_IRQ) == HIGH;
    }

    // UM11495 section 4.3: direction byte, then the complete NCI packet.
    // NCI header byte 2 is the payload length; there is no SPI length prefix.
    bool spi_write_packet(const uint8_t *data, size_t size)
    {
      if (data == nullptr || size < 3 || size > kNciMaxPacket ||
          size != static_cast<size_t>(data[2]) + 3 || irq_asserted())
        return false;
      for (unsigned attempt = 0; attempt < 2; ++attempt)
      {
        if (irq_asserted()) return false;
        nfc_spi.beginTransaction(SPISettings(1000000, MSBFIRST, SPI_MODE0));
        chip_select(true);
        const bool ready = nfc_spi.transfer(0x00) == 0xff;
        if (ready)
          for (size_t i = 0; i < size; ++i) nfc_spi.transfer(data[i]);
        chip_select(false);
        nfc_spi.endTransaction();
        if (ready) return true;
        delay(5); // bounded standby wake-up retry, UM11495 section 4.3.3
      }
      return false;
    }

    bool spi_read_packet(uint8_t *out, size_t capacity, size_t *out_size,
                         uint32_t timeout_ms)
    {
      if (out == nullptr || out_size == nullptr || capacity < 3) return false;
      *out_size = 0;
      const uint32_t started = millis();
      while (!irq_asserted())
      {
        if (millis() - started >= timeout_ms) return false;
        delay(1);
      }
      nfc_spi.beginTransaction(SPISettings(1000000, MSBFIRST, SPI_MODE0));
      chip_select(true);
      nfc_spi.transfer(0xff);
      for (size_t i = 0; i < 3; ++i) out[i] = nfc_spi.transfer(0xff);
      const size_t length = static_cast<size_t>(out[2]) + 3;
      // Drain an oversized packet completely to preserve transport framing.
      for (size_t i = 3; i < length; ++i)
      {
        const uint8_t byte = nfc_spi.transfer(0xff);
        if (i < capacity) out[i] = byte;
      }
      chip_select(false);
      nfc_spi.endTransaction();
      if (length > capacity) return false;
      *out_size = length;
      return true;
    }

    bool send_command(uint8_t group, uint8_t oid, const uint8_t *payload,
                      uint8_t payload_size)
    {
      uint8_t packet[kNciMaxPacket];
      packet[0] = static_cast<uint8_t>(kCommandPacket | (group & 0x0f));
      packet[1] = oid;
      packet[2] = payload_size;
      if (payload_size != 0)
        memcpy(packet + 3, payload, payload_size);
      return spi_write_packet(packet, 3 + payload_size);
    }

    bool wait_for_response(uint8_t group, uint8_t oid, uint8_t *response,
                           size_t response_capacity, size_t *response_size,
                           bool *saw_reset_notification, uint32_t timeout_ms)
    {
      uint8_t packet[kNciMaxPacket];
      const uint32_t started = millis();
      while (millis() - started < timeout_ms)
      {
        const uint32_t elapsed = millis() - started;
        if (elapsed >= timeout_ms) return false;
        size_t size = 0;
        if (!spi_read_packet(packet, sizeof(packet), &size,
                             timeout_ms - elapsed))
          continue;
        if (size < 3)
          continue;
        const uint8_t type = packet[0] & 0xe0;
        const uint8_t packet_group = packet[0] & 0x0f;
        const uint8_t packet_oid = packet[1];
        const size_t length = packet[2];
        if (size != 3 + length || (packet[0] & 0x10) != 0)
          continue;

        // CORE_RESET_NTF follows CORE_RESET_RSP. It must be observed but it is
        // not the response we are waiting for.
        if (type == kNotificationPacket && packet_group == kGidCore &&
            packet_oid == kCoreResetOid)
        {
          if (saw_reset_notification != nullptr)
            *saw_reset_notification = true;
          continue;
        }
        if (type == kResponsePacket && packet_group == group &&
            packet_oid == oid)
        {
          if (length > response_capacity)
            return false;
          if (length != 0)
            memcpy(response, packet + 3, length);
          *response_size = length;
          return true;
        }
      }
      return false;
    }

    bool command_with_response(uint8_t group, uint8_t oid, const uint8_t *payload,
                               uint8_t payload_size, uint8_t *response,
                               size_t response_capacity, size_t *response_size,
                               uint32_t timeout_ms)
    {
      if (!send_command(group, oid, payload, payload_size))
        return false;
      return wait_for_response(group, oid, response, response_capacity,
                               response_size, nullptr, timeout_ms);
    }

    bool nci_initialize()
    {
      pinMode(HEXWALLET_NFC_PIN_IRQ, INPUT);
      pinMode(HEXWALLET_NFC_PIN_CS, OUTPUT);
      digitalWrite(HEXWALLET_NFC_PIN_CS, HIGH);
      pinMode(HEXWALLET_NFC_PIN_VEN, OUTPUT);
      digitalWrite(HEXWALLET_NFC_PIN_VEN, LOW);
      delay(10);
      digitalWrite(HEXWALLET_NFC_PIN_VEN, HIGH);
      delay(20);

      uint8_t response[kNciMaxPayload];
      size_t response_size = 0;

      const uint8_t reset_payload[1] = {0x00}; // keep the current configuration
      if (!send_command(kGidCore, kCoreResetOid, reset_payload,
                        sizeof(reset_payload)))
      {
        return false;
      }
      bool saw_reset_notification = false;
      if (!wait_for_response(kGidCore, kCoreResetOid, response, sizeof(response),
                             &response_size, &saw_reset_notification,
                             kNciResetTimeoutMs))
      {
        return false;
      }
      if (response_size < 1 || response[0] != 0x00)
        return false; // status != OK

      // Wait for CORE_RESET_NTF before the next command, otherwise the controller
      // answers STATUS_REJECTED while it is still restarting.
      const uint32_t notification_started = millis();
      uint8_t packet[kNciMaxPacket];
      while (!saw_reset_notification && millis() - notification_started < kNciResetTimeoutMs)
      {
        size_t size = 0;
        if (!spi_read_packet(packet, sizeof(packet), &size, kNciResetTimeoutMs))
        {
          break;
        }
        if (size >= 3 && size == static_cast<size_t>(packet[2]) + 3 &&
            (packet[0] & 0x10) == 0 && (packet[0] & 0xe0) == kNotificationPacket &&
            (packet[0] & 0x0f) == kGidCore && packet[1] == kCoreResetOid)
        {
          saw_reset_notification = true;
        }
      }
      if (!saw_reset_notification)
        return false;

      const uint8_t init_payload[2] = {0x00, 0x00};
      if (!command_with_response(kGidCore, kCoreInitOid, init_payload,
                                 sizeof(init_payload), response, sizeof(response),
                                 &response_size, kNciResponseTimeoutMs))
      {
        return false;
      }
      if (response_size < 1 || response[0] != 0x00)
        return false;

      const uint8_t discover_map[4] = {0x01, kRfProtocolIsoDep,
                                       0x02, kRfInterfaceIsoDep};
      if (!command_with_response(kGidRf, kRfDiscoverMapOid, discover_map,
                                 sizeof(discover_map), response, sizeof(response),
                                 &response_size, kNciResponseTimeoutMs))
      {
        return false;
      }
      if (response_size < 1 || response[0] != 0x00)
        return false;

      const uint8_t discover[3] = {0x01, kRfNfcAPassiveListen, kRfDiscoveryFrequency};
      if (!command_with_response(kGidRf, kRfDiscoverOid, discover,
                                 sizeof(discover), response, sizeof(response),
                                 &response_size, kNciResponseTimeoutMs))
      {
        return false;
      }
      return response_size >= 1 && response[0] == 0x00;
    }

    bool send_data_packet(uint8_t connection, bool chained, const uint8_t *data,
                          size_t size)
    {
      if (size == 0 || size > kMaxApduChunk)
        return false;
      uint8_t packet[kMaxApduChunk + 3];
      // NCI data header: MT/PBF/connection, RFU, payload length.
      packet[0] = static_cast<uint8_t>(kDataPacket | (chained ? 0x10 : 0x00) |
                                       (connection & 0x0f));
      packet[1] = 0;
      packet[2] = static_cast<uint8_t>(size);
      memcpy(packet + 3, data, size);
      return spi_write_packet(packet, 3 + size);
    }

    void fail_session()
    {
      nfc_port_end_session();
      state = NfcPortState::Error;
    }

    void flush_response()
    {
      if (tx_offset >= tx_size || tx_credits == 0 || irq_asserted()) return;
      const size_t remaining = tx_size - tx_offset;
      const size_t take = remaining < tx_limit ? remaining : tx_limit;
      if (take == 0 || !send_data_packet(0, take < remaining, tx_buffer + tx_offset, take))
      {
        fail_session();
        return;
      }
      if (tx_credits != 0xff) --tx_credits;
      tx_offset += take;
      if (tx_offset == tx_size)
      {
        secure_zero(tx_buffer, sizeof(tx_buffer));
        tx_size = tx_offset = 0;
      }
    }

    void relay_apdu(uint8_t connection)
    {
      (void)connection; // Static RF connection ID is always zero.
      if (apdu_handler == nullptr || apdu_size < 4 || tx_size != 0)
      {
        fail_session();
        return;
      }
      tx_size = apdu_handler(apdu_buffer, apdu_size, tx_buffer, sizeof(tx_buffer));
      secure_zero(apdu_buffer, sizeof(apdu_buffer));
      apdu_size = 0;
      tx_offset = 0;
      transfer_started = millis();
      if (tx_size == 0 || tx_size > sizeof(tx_buffer)) fail_session();
    }

    void handle_data_packet(const uint8_t *packet, size_t size)
    {
      if (size < 3) { fail_session(); return; }
      const bool chained = (packet[0] & 0x10) != 0;
      const uint8_t connection = static_cast<uint8_t>(packet[0] & 0x0f);
      const size_t length = packet[2];
      if (size != 3 + length || packet[1] != 0 || connection != 0 ||
          length == 0 || tx_size != 0)
      { fail_session(); return; }
      if (apdu_size + length > sizeof(apdu_buffer))
      {
        fail_session();
        return;
      }
      if (apdu_size == 0) transfer_started = millis();
      memcpy(apdu_buffer + apdu_size, packet + 3, length);
      apdu_size += length;
      apdu_chained = chained;
      if (!chained)
        relay_apdu(connection);
    }

    void handle_notification(const uint8_t *packet, size_t size)
    {
      if (size < 3) { fail_session(); return; }
      const uint8_t group = packet[0] & 0x0f;
      const uint8_t oid = packet[1];
      const size_t length = packet[2];
      if (size != 3 + length || (packet[0] & 0x10) != 0)
      { fail_session(); return; }
      const uint8_t *payload = packet + 3;

      if (group == kGidCore && oid == 0x06) // CORE_CONN_CREDITS_NTF
      {
        if (length < 1 || length != 1 + 2 * static_cast<size_t>(payload[0]))
        { fail_session(); return; }
        for (size_t i = 1; i < length; i += 2)
        {
          if (payload[i] != 0 || state != NfcPortState::Activated) continue;
          if (tx_credits != 0xff)
          {
            const unsigned total = tx_credits + payload[i + 1];
            if (total >= 0xff) { fail_session(); return; }
            tx_credits = static_cast<uint8_t>(total);
          }
        }
        return;
      }
      if (group == kGidRf && oid == kRfIntfActivatedOid)
      {
        nfc_port_end_session();
        // Discovery ID is not a status byte or a connection ID.
        // Fields after RF technology parameters have variable offsets.
        if (length < 11 || payload[1] != kRfInterfaceIsoDep ||
            payload[2] != kRfProtocolIsoDep || payload[3] != kRfNfcAPassiveListen ||
            payload[4] == 0)
        { fail_session(); return; }
        const size_t tail = 7 + static_cast<size_t>(payload[6]);
        if (tail + 4 > length || payload[tail] != kRfNfcAPassiveListen ||
            tail + 4 + payload[tail + 3] != length)
        { fail_session(); return; }
        connection_id = 0;
        tx_limit = payload[4] < kMaxApduChunk ? payload[4] : kMaxApduChunk;
        tx_credits = payload[5];
        state = NfcPortState::Activated;
        return;
      }
      if (group == kGidRf && oid == kRfDeactivateOid)
      {
        nfc_port_end_session();
        // Discovery and sleep can await another activation. Idle needs re-init.
        state = length == 2 && payload[0] >= 1 && payload[0] <= 3
                    ? NfcPortState::Ready : NfcPortState::Error;
        return;
      }
      if (group == kGidCore && (oid == 0x00 || oid == 0x07 || oid == 0x08))
        fail_session();

    }

#endif // HEXWALLET_NFC_PORT_AVAILABLE

  } // namespace

  bool nfc_port_configured()
  {
#if HEXWALLET_NFC_PORT_AVAILABLE
    return true;
#else
    return false;
#endif
  }

  NfcPortState nfc_port_state()
  {
#if HEXWALLET_NFC_PORT_AVAILABLE
    return state;
#else
    return NfcPortState::NotConfigured;
#endif
  }

  const char *nfc_port_state_text(NfcPortState value)
  {
    switch (value)
    {
    case NfcPortState::NotConfigured:
      return "not-configured";
    case NfcPortState::InitFailed:
      return "init-failed";
    case NfcPortState::Ready:
      return "ready";
    case NfcPortState::Activated:
      return "activated";
    case NfcPortState::Error:
      return "error";
    }
    return "unknown";
  }

  bool nfc_port_begin(NfcApduHandler handler, NfcSessionLostHandler lost_handler)
  {
#if HEXWALLET_NFC_PORT_AVAILABLE
    if (handler == nullptr || lost_handler == nullptr)
      return false;
    nfc_port_end_session();
    apdu_handler = handler;
    session_lost = lost_handler;
    if (!bus_ready)
    {
      nfc_spi.begin(HEXWALLET_NFC_PIN_SCK, HEXWALLET_NFC_PIN_MISO,
                    HEXWALLET_NFC_PIN_MOSI, HEXWALLET_NFC_PIN_CS);
      bus_ready = true;
    }
    // Re-running the sequence is safe: it is exactly what a field reset does.
    const bool ok = nci_initialize();
    state = ok ? NfcPortState::Ready : NfcPortState::InitFailed;
    if (!ok)
    {
      connection_id = 0;
      apdu_size = 0;
      apdu_chained = false;
      secure_zero(apdu_buffer, sizeof(apdu_buffer));
    }
    return ok;
#else
    (void)handler;
    (void)lost_handler;
    return false;
#endif
  }

  void nfc_port_end_session()
  {
#if HEXWALLET_NFC_PORT_AVAILABLE
    clear_session();
    connection_id = 0;
    apdu_size = 0;
    apdu_chained = false;
    secure_zero(apdu_buffer, sizeof(apdu_buffer));
    if (state == NfcPortState::Activated)
      state = NfcPortState::Ready;
#endif
  }

  void nfc_port_service(uint32_t now_ms)
  {
#if HEXWALLET_NFC_PORT_AVAILABLE
    if (state != NfcPortState::Ready && state != NfcPortState::Activated)
      return;
    if (now_ms - last_poll_ms < 2)
      return;
    last_poll_ms = now_ms;
    if ((apdu_size != 0 || tx_size != 0) && millis() - transfer_started >= 2000UL)
    { fail_session(); return; }
    if (!irq_asserted())
    {
      flush_response();
      return;
    }

    uint8_t packet[kNciMaxPacket];
    size_t size = 0;
    if (!spi_read_packet(packet, sizeof(packet), &size, 0) || size < 3)
    { fail_session(); return; }
    const uint8_t type = packet[0] & 0xe0;
    if (type == kDataPacket)
    {
      if (state != NfcPortState::Activated)
        return;
      handle_data_packet(packet, size);
    }
    else if (type == kNotificationPacket)
    {
      handle_notification(packet, size);
    }
#else
    (void)now_ms;
#endif
  }

} // namespace hexwallet
