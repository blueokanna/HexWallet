#include "WalletNfcPort.h"

#include <Arduino.h>
#include <SPI.h>
#include <string.h>

#include "WalletBoardPins.h"
#include "WalletSharedSpi.h"
#include "WalletSecurity.h"
#include "SensitiveValue.h"

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

    constexpr uint8_t kRfNfcAPassiveListen = 0x80;
    constexpr uint8_t kRfInterfaceIsoDep = 0x02;
    constexpr uint8_t kRfProtocolIsoDep = 0x04;
    constexpr uint8_t kRfDiscoveryFrequency = 0x01;

#if HEXWALLET_NFC_PORT_AVAILABLE

#if defined(HEXWALLET_SHARED_SPI_PIN_SCK)
    static_assert(HEXWALLET_SHARED_SPI_PIN_SCK == HEXWALLET_NFC_PIN_SCK &&
                  HEXWALLET_SHARED_SPI_PIN_MISO == HEXWALLET_NFC_PIN_MISO &&
                  HEXWALLET_SHARED_SPI_PIN_MOSI == HEXWALLET_NFC_PIN_MOSI,
                  "NFC and panel must use the same SPI pins");
    SPIClass &nfc_spi = SPI;
#else
    SPIClass nfc_spi(HSPI);
#endif
    NfcPortState state = NfcPortState::InitFailed;
    const char *last_error = "PN7161 not initialized";
    NfcApduHandler apdu_handler = nullptr;
    NfcSessionLostHandler session_lost = nullptr;
    uint8_t tx_buffer[kMaxApduSize];
    size_t tx_size = 0, tx_offset = 0;
    uint8_t tx_limit = 0, tx_credits = 0;
    uint32_t transfer_started = 0;

    bool polling_tags = false;

    void clear_session()
    {
      secure_zero(tx_buffer, sizeof(tx_buffer));
      tx_size = tx_offset = 0;
      tx_limit = tx_credits = 0;
      if (!polling_tags && session_lost != nullptr)
        session_lost();
    }
    bool bus_ready = false;
    uint8_t connection_id = 0;
    uint8_t apdu_buffer[kMaxApduSize];
    size_t apdu_size = 0;
    bool apdu_chained = false;
    uint32_t last_poll_ms = 0;

    enum class TagStep { Discover, SelectApp, SelectCC, ReadCC, SelectFile, ReadLength, ReadText };
    struct BackupReader {
      TagStep step;
      uint32_t started;
      uint16_t file_id, file_size, max_read;
      size_t length, received, chunk;
      uint8_t record[96];
      char key[65];
    };
    BackupReader reader{};
    NfcBackupStatus read_status = NfcBackupStatus::Idle;

    void finish_read(NfcBackupStatus status) {
      if (status != NfcBackupStatus::Complete) secure_zero(reader.key, sizeof(reader.key));
      secure_zero(reader.record, sizeof(reader.record));
      secure_zero(apdu_buffer, sizeof(apdu_buffer));
      secure_zero(tx_buffer, sizeof(tx_buffer));
      apdu_size = tx_size = tx_offset = 0;
      read_status = status;
    }

    bool chip_select(bool selected)
    {
#if defined(HEXWALLET_SHARED_SPI_PIN_SCK)
      return selected ? board_spi_select(HEXWALLET_NFC_PIN_CS)
                      : board_spi_deselect(HEXWALLET_NFC_PIN_CS);
#else
      digitalWrite(HEXWALLET_NFC_PIN_CS, selected ? LOW : HIGH);
      return true;
#endif
    }

    bool irq_asserted()
    {
      return digitalRead(HEXWALLET_NFC_PIN_IRQ) == HIGH;
    }

    bool spi_write_packet(const uint8_t *data, size_t size)
    {
      if (data == nullptr || size < 3 || size > kNciMaxPacket ||
          size != static_cast<size_t>(data[2]) + 3 || irq_asserted())
        return false;
      for (unsigned attempt = 0; attempt < 2; ++attempt)
      {
        if (irq_asserted())
          return false;
        nfc_spi.beginTransaction(SPISettings(1000000, MSBFIRST, SPI_MODE0));
        if (!chip_select(true)) {
          nfc_spi.endTransaction();
          return false;
        }
        const bool ready = nfc_spi.transfer(0x00) == 0xff;
        if (ready)
          for (size_t i = 0; i < size; ++i)
            nfc_spi.transfer(data[i]);
        const bool released = chip_select(false);
        nfc_spi.endTransaction();
        if (!released) return false;
        if (ready)
          return true;
        delay(5);
      }
      return false;
    }

    bool spi_read_packet(uint8_t *out, size_t capacity, size_t *out_size,
                         uint32_t timeout_ms)
    {
      if (out == nullptr || out_size == nullptr || capacity < 3)
        return false;
      *out_size = 0;
      const uint32_t started = millis();
      while (!irq_asserted())
      {
        if (millis() - started >= timeout_ms)
          return false;
        delay(1);
      }
      nfc_spi.beginTransaction(SPISettings(1000000, MSBFIRST, SPI_MODE0));
      if (!chip_select(true)) {
        nfc_spi.endTransaction();
        return false;
      }
      nfc_spi.transfer(0xff);
      for (size_t i = 0; i < 3; ++i)
        out[i] = nfc_spi.transfer(0xff);
      const size_t length = static_cast<size_t>(out[2]) + 3;
      for (size_t i = 3; i < length; ++i)
      {
        const uint8_t byte = nfc_spi.transfer(0xff);
        if (i < capacity)
          out[i] = byte;
      }
      const bool released = chip_select(false);
      nfc_spi.endTransaction();
      if (!released || length > capacity)
        return false;
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
        if (elapsed >= timeout_ms)
          return false;
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

    bool nci_initialize(bool poll = false)
    {
      pinMode(HEXWALLET_NFC_PIN_IRQ, INPUT);
      pinMode(HEXWALLET_NFC_PIN_VEN, OUTPUT);
      digitalWrite(HEXWALLET_NFC_PIN_VEN, LOW);
#if defined(HEXWALLET_NFC_PIN_DWL_REQ)
      pinMode(HEXWALLET_NFC_PIN_DWL_REQ, OUTPUT);
      digitalWrite(HEXWALLET_NFC_PIN_DWL_REQ, LOW);
#endif
      delay(10);
      digitalWrite(HEXWALLET_NFC_PIN_VEN, HIGH);
      delay(20);

      uint8_t response[kNciMaxPayload];
      size_t response_size = 0;

      last_error = "CORE_RESET write failed";
      const uint8_t reset_payload[1] = {0x00};
      if (!send_command(kGidCore, kCoreResetOid, reset_payload,
                        sizeof(reset_payload)))
      {
        return false;
      }
      last_error = "CORE_RESET response missing or invalid";
      bool saw_reset_notification = false;
      if (!wait_for_response(kGidCore, kCoreResetOid, response, sizeof(response),
                             &response_size, &saw_reset_notification,
                             kNciResetTimeoutMs))
      {
        return false;
      }
      if (response_size < 1 || response[0] != 0x00)
        return false;
      last_error = "CORE_RESET notification missing";
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

      last_error = "CORE_INIT failed";
      const uint8_t init_payload[2] = {0x00, 0x00};
      if (!command_with_response(kGidCore, kCoreInitOid, init_payload,
                                 sizeof(init_payload), response, sizeof(response),
                                 &response_size, kNciResponseTimeoutMs))
      {
        return false;
      }
      if (response_size < 1 || response[0] != 0x00)
        return false;

      last_error = "RF_DISCOVER_MAP failed";
      const uint8_t discover_map[4] = {0x01, kRfProtocolIsoDep,
                                       uint8_t(poll ? 0x01 : 0x02), kRfInterfaceIsoDep};
      if (!command_with_response(kGidRf, kRfDiscoverMapOid, discover_map,
                                 sizeof(discover_map), response, sizeof(response),
                                 &response_size, kNciResponseTimeoutMs))
      {
        return false;
      }
      if (response_size < 1 || response[0] != 0x00)
        return false;

      last_error = "RF_DISCOVER failed";
      const uint8_t discover[3] = {0x01, uint8_t(poll ? 0x00 : kRfNfcAPassiveListen), kRfDiscoveryFrequency};
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
      SensitiveValue<uint8_t[kMaxApduChunk + 3]> storage;
      auto &packet = storage.get();
      // NCI data header: MT/PBF/connection, RFU, payload length.
      packet[0] = static_cast<uint8_t>(kDataPacket | (chained ? 0x10 : 0x00) |
                                       (connection & 0x0f));
      packet[1] = 0;
      packet[2] = static_cast<uint8_t>(size);
      memcpy(packet + 3, data, size);
      return spi_write_packet(packet, 3 + size);
    }

    void fail_session(const char *reason)
    {
      if (polling_tags && read_status == NfcBackupStatus::Pending) finish_read(NfcBackupStatus::Controller);
      nfc_port_end_session();
      last_error = reason;
      state = NfcPortState::Error;
    }

    void flush_response()
    {
      if (tx_offset >= tx_size || tx_credits == 0 || irq_asserted())
        return;
      const size_t remaining = tx_size - tx_offset;
      const size_t take = remaining < tx_limit ? remaining : tx_limit;
      if (take == 0 || !send_data_packet(0, take < remaining, tx_buffer + tx_offset, take))
      {
        fail_session("SPI response write failed");
        return;
      }
      if (tx_credits != 0xff)
        --tx_credits;
      tx_offset += take;
      if (tx_offset == tx_size)
      {
        secure_zero(tx_buffer, sizeof(tx_buffer));
        tx_size = tx_offset = 0;
      }
    }

    void queue_reader_command(const uint8_t *command, size_t length) {
      memcpy(tx_buffer, command, length);
      tx_size = length;
      tx_offset = 0;
      transfer_started = millis();
    }

    void read_binary(uint16_t offset, size_t length) {
      const uint8_t command[] = {0, 0xb0, uint8_t(offset >> 8), uint8_t(offset), uint8_t(length)};
      reader.chunk = length;
      queue_reader_command(command, sizeof(command));
    }

    void select_file(uint16_t id) {
      const uint8_t command[] = {0, 0xa4, 0, 0x0c, 2, uint8_t(id >> 8), uint8_t(id)};
      queue_reader_command(command, sizeof(command));
    }

    bool extract_text_key() {
      const auto *record = reader.record;
      // MB, ME, SR, TNF well-known, exactly one UTF-8 RTD Text record.
      if (reader.length < 5 || record[0] != 0xd1 || record[1] != 1 ||
          record[2] + 4U != reader.length || record[3] != 'T' || (record[4] & 0xc0)) return false;
      const size_t offset = 5U + record[4];
      if (offset > reader.length) return false;
      const size_t length = reader.length - offset;
      if (length != 51 && length != 52 && length != 58 && length != 64) return false;
      for (size_t i = offset; i < reader.length; ++i) {
        const auto c = record[i];
        if (!(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z')) return false;
      }
      memcpy(reader.key, record + offset, length);
      reader.key[length] = 0;
      return true;
    }

    void reader_response(const uint8_t *data, size_t length) {
      if (length < 2) {
        finish_read(NfcBackupStatus::InvalidRecord);
        return;
      }
      const uint16_t sw = uint16_t(data[length - 2] << 8 | data[length - 1]);
      if (sw != 0x9000) {
        if (sw == 0x6a82) finish_read(NfcBackupStatus::MissingFile);
        else if (sw == 0x6982 || sw == 0x6985) finish_read(NfcBackupStatus::AccessDenied);
        else finish_read(NfcBackupStatus::CommandRejected);
        return;
      }
      length -= 2;
      switch (reader.step) {
        case TagStep::SelectApp:
          reader.step = TagStep::SelectCC;
          select_file(0xe103);
          return;
        case TagStep::SelectCC:
          reader.step = TagStep::ReadCC;
          read_binary(0, 15);
          return;
        case TagStep::ReadCC:
          // NFC Forum Type 4 mapping v2, first standard NDEF File Control TLV.
          if (length != 15 || (data[0] << 8 | data[1]) < 15 || (data[2] >> 4) != 2 ||
              data[7] != 4 || data[8] != 6) break;
          if (data[13] != 0) { finish_read(NfcBackupStatus::AccessDenied); return; }
          reader.max_read = uint16_t(data[3] << 8 | data[4]);
          reader.file_id = uint16_t(data[9] << 8 | data[10]);
          reader.file_size = uint16_t(data[11] << 8 | data[12]);
          if (reader.max_read < 15 || !reader.file_id || reader.file_id == 0x3f00 || reader.file_id == 0x3fff ||
              reader.file_id == 0xe102 || reader.file_id == 0xe103 || reader.file_id == 0xffff) break;
          reader.step = TagStep::SelectFile;
          select_file(reader.file_id);
          return;
        case TagStep::SelectFile:
          reader.step = TagStep::ReadLength;
          read_binary(0, 2);
          return;
        case TagStep::ReadLength:
          if (length != 2) break;
          reader.length = data[0] << 8 | data[1];
          if (!reader.length || reader.length > sizeof(reader.record) || reader.length + 2 > reader.file_size) break;
          reader.step = TagStep::ReadText;
          reader.received = 0;
          break;
        case TagStep::ReadText:
          if (length != reader.chunk || length > reader.length - reader.received) {
            finish_read(NfcBackupStatus::InvalidRecord); return;
          }
          memcpy(reader.record + reader.received, data, length);
          reader.received += length;
          if (reader.received == reader.length) {
            finish_read(extract_text_key() ? NfcBackupStatus::Complete : NfcBackupStatus::InvalidRecord);
            return;
          }
          break;
        default: break;
      }
      if (reader.step == TagStep::ReadText) {
        const size_t left = reader.length - reader.received;
        read_binary(uint16_t(2 + reader.received), left < reader.max_read ? left : reader.max_read);
      } else finish_read(NfcBackupStatus::InvalidRecord);
    }

    void relay_apdu(uint8_t connection)
    {
      (void)connection;
      if (polling_tags) {
        reader_response(apdu_buffer, apdu_size);
        secure_zero(apdu_buffer, sizeof(apdu_buffer));
        apdu_size = 0;
        return;
      }
      if (apdu_handler == nullptr || apdu_size < 4 || tx_size != 0)
      {
        fail_session("APDU handler unavailable, busy or request too short");
        return;
      }
      tx_size = apdu_handler(apdu_buffer, apdu_size, tx_buffer, sizeof(tx_buffer));
      secure_zero(apdu_buffer, sizeof(apdu_buffer));
      apdu_size = 0;
      tx_offset = 0;
      transfer_started = millis();
      if (tx_size == 0 || tx_size > sizeof(tx_buffer))
        fail_session("APDU response rejected or oversized");
    }

    void handle_data_packet(const uint8_t *packet, size_t size)
    {
      if (size < 3)
      {
        fail_session("NCI data header truncated");
        return;
      }
      const bool chained = (packet[0] & 0x10) != 0;
      const uint8_t connection = static_cast<uint8_t>(packet[0] & 0x0f);
      const size_t length = packet[2];
      if (size != 3 + length || packet[1] != 0 || connection != 0 ||
          length == 0 || tx_size != 0)
      {
        fail_session("Invalid NCI data header or interleaved APDU");
        return;
      }
      if (apdu_size + length > sizeof(apdu_buffer))
      {
        fail_session("APDU exceeds 1024 bytes");
        return;
      }
      if (apdu_size == 0)
        transfer_started = millis();
      memcpy(apdu_buffer + apdu_size, packet + 3, length);
      apdu_size += length;
      apdu_chained = chained;
      if (!chained)
        relay_apdu(connection);
    }

    void handle_notification(const uint8_t *packet, size_t size)
    {
      if (size < 3)
      {
        fail_session("NCI notification header truncated");
        return;
      }
      const uint8_t group = packet[0] & 0x0f;
      const uint8_t oid = packet[1];
      const size_t length = packet[2];
      if (size != 3 + length || (packet[0] & 0x10) != 0)
      {
        fail_session("Invalid NCI notification length or fragmentation");
        return;
      }
      const uint8_t *payload = packet + 3;

      if (group == kGidCore && oid == 0x06) // CORE_CONN_CREDITS_NTF
      {
        if (length < 1 || length != 1 + 2 * static_cast<size_t>(payload[0]))
        {
          fail_session("Invalid CORE_CONN_CREDITS length");
          return;
        }
        for (size_t i = 1; i < length; i += 2)
        {
          if (payload[i] != 0 || state != NfcPortState::Activated)
            continue;
          if (tx_credits != 0xff)
          {
            const unsigned total = tx_credits + payload[i + 1];
            if (total >= 0xff)
            {
              fail_session("CORE_CONN_CREDITS overflow");
              return;
            }
            tx_credits = static_cast<uint8_t>(total);
          }
        }
        return;
      }
      if (polling_tags && group == kGidRf && oid == kRfDiscoverOid) {
        // Host selection is required when discovery finds multiple targets.
        finish_read(NfcBackupStatus::UnsupportedTag);
        return;
      }
      if (group == kGidRf && oid == kRfIntfActivatedOid)
      {
        const uint8_t mode = polling_tags ? 0x00 : kRfNfcAPassiveListen;
        if (polling_tags && reader.step != TagStep::Discover) { finish_read(NfcBackupStatus::TagLost); return; }
        nfc_port_end_session();
        if (length < 11 || payload[1] != kRfInterfaceIsoDep ||
            payload[2] != kRfProtocolIsoDep || payload[3] != mode ||
            payload[4] == 0)
        {
          if (polling_tags) finish_read(NfcBackupStatus::UnsupportedTag);
          else fail_session("Unsupported RF activation");
          return;
        }
        const size_t tail = 7 + static_cast<size_t>(payload[6]);
        if (tail + 4 > length || payload[tail] != mode ||
            tail + 4 + payload[tail + 3] != length)
        {
          fail_session("Invalid RF activation parameters");
          return;
        }
        connection_id = 0;
        tx_limit = payload[4] < kMaxApduChunk ? payload[4] : kMaxApduChunk;
        tx_credits = payload[5];
        last_error = nullptr;
        state = NfcPortState::Activated;
        if (polling_tags) {
          const uint8_t select_ndef[] = {0, 0xa4, 0x04, 0, 7, 0xd2, 0x76, 0, 0, 0x85, 1, 1, 0};
          reader.step = TagStep::SelectApp;
          queue_reader_command(select_ndef, sizeof(select_ndef));
        }
        return;
      }
      if (group == kGidRf && oid == kRfDeactivateOid)
      {
        if (polling_tags) { finish_read(NfcBackupStatus::TagLost); return; }
        nfc_port_end_session();
        state = length == 2 && payload[0] >= 1 && payload[0] <= 3
                    ? NfcPortState::Ready
                    : NfcPortState::Error;
        last_error = state == NfcPortState::Error ? "Unexpected RF deactivation" : nullptr;
        return;
      }
      if (group == kGidCore && (oid == 0x00 || oid == 0x07 || oid == 0x08))
        fail_session("NCI controller reset or interface error");
    }

#endif

  }

  bool nfc_port_configured()
  {
#if HEXWALLET_NFC_PORT_AVAILABLE
    return true;
#else
    return false;
#endif
  }

  const char *nfc_port_error()
  {
#if HEXWALLET_NFC_PORT_AVAILABLE
    return last_error;
#else
    return "PN7161 pins not configured";
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
    if (handler == nullptr || lost_handler == nullptr) {
      last_error = "NFC callbacks missing";
      return false;
    }
    nfc_port_end_session();
    polling_tags = false;
    read_status = NfcBackupStatus::Idle;
    secure_zero(&reader, sizeof(reader));
    apdu_handler = handler;
    session_lost = lost_handler;
    if (!bus_ready)
    {
#if defined(HEXWALLET_SHARED_SPI_PIN_SCK)
      if (!board_shared_spi_begin())
#else
      pinMode(HEXWALLET_NFC_PIN_CS, OUTPUT);
      digitalWrite(HEXWALLET_NFC_PIN_CS, HIGH);
      if (!nfc_spi.begin(HEXWALLET_NFC_PIN_SCK, HEXWALLET_NFC_PIN_MISO,
                         HEXWALLET_NFC_PIN_MOSI, -1))
#endif
      {
        last_error = "SPI bus initialization failed";
        state = NfcPortState::InitFailed;
        return false;
      }
      bus_ready = true;
    }
    const bool ok = nci_initialize();
    if (ok) last_error = nullptr;
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
    if (polling_tags) {
      if (read_status == NfcBackupStatus::Pending && now_ms - reader.started >= 30000U) finish_read(NfcBackupStatus::Timeout);
      if (read_status != NfcBackupStatus::Pending) {
        nfc_port_end_session();
        polling_tags = false;
        if (nci_initialize()) { state = NfcPortState::Ready; last_error = nullptr; }
        else { state = NfcPortState::InitFailed; finish_read(NfcBackupStatus::Controller); }
        return;
      }
    }
    if (state != NfcPortState::Ready && state != NfcPortState::Activated)
      return;
    if (now_ms - last_poll_ms < 2)
      return;
    last_poll_ms = now_ms;
    if ((apdu_size != 0 || tx_size != 0 || (polling_tags && state == NfcPortState::Activated)) && millis() - transfer_started >= 2000UL)
    {
      if (polling_tags) finish_read(NfcBackupStatus::Timeout);
      else fail_session("APDU transfer timed out");
      return;
    }
    if (!irq_asserted())
    {
      flush_response();
      return;
    }

    SensitiveValue<uint8_t[kNciMaxPacket]> storage;
    auto &packet = storage.get();
    size_t size = 0;
    if (!spi_read_packet(packet, sizeof(packet), &size, 0) || size < 3)
    {
      fail_session("SPI NCI packet read failed");
      return;
    }
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

  NfcBackupStatus nfc_backup_start() {
#if HEXWALLET_NFC_PORT_AVAILABLE
    if (polling_tags || state == NfcPortState::Activated) return NfcBackupStatus::Busy;
    if (!bus_ready || state != NfcPortState::Ready) return NfcBackupStatus::Controller;
    secure_zero(&reader, sizeof(reader));
    polling_tags = true;
    reader.started = millis();
    read_status = nci_initialize(true) ? NfcBackupStatus::Pending : NfcBackupStatus::Controller;
    return read_status;
#else
    return NfcBackupStatus::Controller;
#endif
  }

  NfcBackupStatus nfc_backup_take(char (&key)[65]) {
    secure_zero(key, sizeof(key));
#if HEXWALLET_NFC_PORT_AVAILABLE
    if (polling_tags) return NfcBackupStatus::Pending;
    const auto status = read_status;
    if (status == NfcBackupStatus::Complete) memcpy(key, reader.key, sizeof(key));
    secure_zero(&reader, sizeof(reader));
    read_status = NfcBackupStatus::Idle;
    return status;
#else
    return NfcBackupStatus::Controller;
#endif
  }

  void nfc_backup_cancel() {
#if HEXWALLET_NFC_PORT_AVAILABLE
    if (polling_tags) finish_read(NfcBackupStatus::Idle);
    secure_zero(&reader, sizeof(reader));
    read_status = NfcBackupStatus::Idle;
#endif
  }

}
