#include "QrlTransaction.h"

#include <stdio.h>
#include <string.h>

#include "ChainCommon.h"
#include "CryptoPrimitives.h"
#include "SensitiveValue.h"

namespace hexwallet
{
  namespace
  {

    struct QrlOutput
    {
      uint8_t address[kQrlAddressBinarySize];
      uint64_t amount;
    };

    struct QrlRequest
    {
      uint64_t fee;
      uint32_t nonce;
      uint16_t message_size;
      const uint8_t *message;
      uint8_t output_count;
      QrlOutput outputs[kQrlMaxOutputs];
    };

    uint16_t read_be16(const uint8_t *data)
    {
      return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | data[1]);
    }

    uint32_t read_be32(const uint8_t *data)
    {
      uint32_t value = 0;
      for (size_t index = 0; index < 4; ++index)
        value = (value << 8) | data[index];
      return value;
    }

    uint64_t read_be64(const uint8_t *data)
    {
      uint64_t value = 0;
      for (size_t index = 0; index < 8; ++index)
        value = (value << 8) | data[index];
      return value;
    }

    void write_be64(uint64_t value, uint8_t out[8])
    {
      for (size_t index = 8; index != 0; --index)
      {
        out[index - 1] = static_cast<uint8_t>(value);
        value >>= 8;
      }
    }

    ChainError parse_payload(const uint8_t *payload, size_t size, QrlRequest *request)
    {
      if (payload == nullptr || request == nullptr)
        return ChainError::InvalidArgument;
      if (size < kQrlPayloadFixedSize + 1 || memcmp(payload, "QRL1", 4) != 0)
      {
        return ChainError::Malformed;
      }
      memset(request, 0, sizeof(*request));
      size_t offset = 4;
      if (payload[offset++] != 0)
        return ChainError::Malformed; // reserved flags
      request->fee = read_be64(payload + offset);
      offset += 8;
      request->nonce = read_be32(payload + offset);
      offset += 4;
      request->message_size = read_be16(payload + offset);
      offset += 2;
      if (request->message_size > kQrlMaxMessageSize)
        return ChainError::Malformed;
      if (size - offset < request->message_size)
        return ChainError::Malformed;
      request->message = payload + offset;
      offset += request->message_size;
      if (offset >= size)
        return ChainError::Malformed;
      request->output_count = payload[offset++];
      if (request->output_count == 0 || request->output_count > kQrlMaxOutputs)
      {
        return ChainError::Malformed;
      }
      if (size - offset != static_cast<size_t>(request->output_count) *
                               (kQrlAddressBinarySize + 8))
      {
        return ChainError::Malformed;
      }
      for (uint8_t index = 0; index < request->output_count; ++index)
      {
        QrlOutput &output = request->outputs[index];
        memcpy(output.address, payload + offset, kQrlAddressBinarySize);
        offset += kQrlAddressBinarySize;
        output.amount = read_be64(payload + offset);
        offset += 8;
        if (!qrl_address_bytes_valid(output.address))
          return ChainError::Malformed;
        if (output.amount == 0)
          return ChainError::InvalidAmount;
      }
      return ChainError::Ok;
    }

    // qrllib TransferTransaction.get_data_bytes(): the exact bytes the node hashes.
    bool build_preimage(const QrlRequest &request,
                        const uint8_t sender[kQrlAddressBinarySize], uint8_t *out,
                        size_t capacity, size_t *out_size)
    {
      const size_t needed = kQrlAddressBinarySize + 8 + request.message_size +
                            static_cast<size_t>(request.output_count) *
                                (kQrlAddressBinarySize + 8);
      if (out == nullptr || out_size == nullptr || capacity < needed)
        return false;
      size_t offset = 0;
      memcpy(out + offset, sender, kQrlAddressBinarySize);
      offset += kQrlAddressBinarySize;
      write_be64(request.fee, out + offset);
      offset += 8;
      if (request.message_size != 0)
      {
        memcpy(out + offset, request.message, request.message_size);
        offset += request.message_size;
      }
      for (uint8_t index = 0; index < request.output_count; ++index)
      {
        memcpy(out + offset, request.outputs[index].address, kQrlAddressBinarySize);
        offset += kQrlAddressBinarySize;
        write_be64(request.outputs[index].amount, out + offset);
        offset += 8;
      }
      *out_size = offset;
      return true;
    }

    bool total_amount(const QrlRequest &request, uint64_t *out)
    {
      uint64_t total = 0;
      for (uint8_t index = 0; index < request.output_count; ++index)
      {
        const uint64_t amount = request.outputs[index].amount;
        if (total > UINT64_MAX - amount)
          return false;
        total += amount;
      }
      *out = total;
      return true;
    }

    ChainError map_ots_error(QrlOtsError error)
    {
      switch (error)
      {
      case QrlOtsError::Ok:
        return ChainError::Ok;
      case QrlOtsError::InvalidArgument:
        return ChainError::InvalidArgument;
      case QrlOtsError::Exhausted:
        return ChainError::Unsupported;
      case QrlOtsError::Unknown:
      case QrlOtsError::StorageFailure:
      case QrlOtsError::WrongAccount:
        return ChainError::StorageUnavailable;
      }
      return ChainError::StorageUnavailable;
    }

  } // namespace

  ChainError qrl_review_payload(const uint8_t *payload, size_t size,
                                const char *sender, ChainReview *review,
                                uint8_t digest[32])
  {
    if (sender == nullptr || review == nullptr || digest == nullptr)
    {
      return ChainError::InvalidArgument;
    }
    QrlRequest request;
    ChainError error = parse_payload(payload, size, &request);
    if (error != ChainError::Ok)
      return error;
    uint8_t sender_bytes[kQrlAddressBinarySize];
    if (!qrl_address_decode(sender, sender_bytes))
      return ChainError::WrongWallet;

    uint8_t preimage[kQrlPreimageSize];
    size_t preimage_size = 0;
    const bool built = build_preimage(request, sender_bytes, preimage,
                                      sizeof(preimage), &preimage_size);
    const bool hashed = built && crypto_sha256(preimage, preimage_size, digest);
    secure_zero(preimage, sizeof(preimage));
    secure_zero(sender_bytes, sizeof(sender_bytes));
    if (!hashed)
      return ChainError::CryptoFailure;

    uint64_t total = 0;
    if (!total_amount(request, &total))
      return ChainError::InvalidAmount;

    memset(review, 0, sizeof(*review));
    if (!chain_copy_text(review->symbol, sizeof(review->symbol), "QRL") ||
        !chain_copy_text(review->sender, sizeof(review->sender), sender))
    {
      return ChainError::BufferTooSmall;
    }
    char address_text[kQrlAddressTextSize];
    uint8_t address[kQrlAddressBinarySize];
    memcpy(address, request.outputs[0].address, sizeof(address));
    const WalletError encoded = qrl_address_text(address, address_text,
                                                 sizeof(address_text));
    secure_zero(address, sizeof(address));
    if (encoded != WalletError::Ok ||
        !chain_copy_text(review->recipient, sizeof(review->recipient), address_text))
    {
      return ChainError::BufferTooSmall;
    }
    char amount[32];
    if (!chain_format_units(total, kQrlDecimals, "QRL", amount, sizeof(amount)) ||
        !chain_copy_text(review->amount, sizeof(review->amount), amount))
    {
      return ChainError::BufferTooSmall;
    }
    char fee[32];
    if (!chain_format_units(request.fee, kQrlDecimals, "QRL", fee, sizeof(fee)) ||
        !chain_copy_text(review->fee, sizeof(review->fee), fee))
    {
      return ChainError::BufferTooSmall;
    }
    char hash_text[kSha256Size * 2 + 1];
    chain_hex(digest, kSha256Size, hash_text, sizeof(hash_text));
    const int written = snprintf(
        review->extra, sizeof(review->extra),
        "NONCE %lu\nOUTPUTS %u\nMESSAGE %u B\nDATA HASH %s",
        static_cast<unsigned long>(request.nonce),
        static_cast<unsigned>(request.output_count),
        static_cast<unsigned>(request.message_size), hash_text);
    if (written < 0 || static_cast<size_t>(written) >= sizeof(review->extra))
    {
      return ChainError::BufferTooSmall;
    }
    return ChainError::Ok;
  }

  ChainError qrl_sign_payload(QrlOtsSlotPort *port, const uint8_t *payload,
                              size_t size, const char *sender,
                              const uint8_t seed[kSeedSize],
                              uint32_t address_index, uint8_t *out,
                              size_t *in_out_size)
  {
    if (in_out_size == nullptr)
      return ChainError::InvalidArgument;
    const size_t capacity = *in_out_size;
    *in_out_size = 0;
    if (out != nullptr)
      secure_zero(out, capacity);
    if (port == nullptr)
      port = qrl_ots_platform_port();
    if (payload == nullptr || sender == nullptr || seed == nullptr || out == nullptr)
    {
      return ChainError::InvalidArgument;
    }
    if (port == nullptr)
      return ChainError::StorageUnavailable;

    QrlRequest request;
    ChainError error = parse_payload(payload, size, &request);
    if (error != ChainError::Ok)
      return error;
    uint8_t sender_bytes[kQrlAddressBinarySize];
    if (!qrl_address_decode(sender, sender_bytes))
      return ChainError::WrongWallet;

    SensitiveValue<uint8_t[kQrlSeedSize]> qrl_seed;
    SensitiveValue<uint8_t[kQrlPublicKeySize]> public_key;
    // The signing key must be the account the review displayed. Signing with a
    // different key would at best waste the signature and at worst spend a
    // one-time leaf of an account the user never saw.
    WalletError wallet_error = qrl_seed_from_bip39(seed, address_index, qrl_seed.get());
    if (wallet_error == WalletError::Ok)
    {
      wallet_error = qrl_xmss_public_key(qrl_seed.get(), kQrlDefaultHeight,
                                         public_key.get());
    }
    uint8_t derived_address[kQrlAddressBinarySize];
    if (wallet_error == WalletError::Ok)
    {
      wallet_error = qrl_address_bytes_from_public_key(public_key.get(),
                                                       derived_address);
    }
    const bool same_account =
        wallet_error == WalletError::Ok &&
        chain_constant_time_equal(derived_address, sender_bytes, kQrlAddressBinarySize);
    secure_zero(derived_address, sizeof(derived_address));
    if (!same_account)
    {
      secure_zero(sender_bytes, sizeof(sender_bytes));
      return wallet_error == WalletError::Ok ? ChainError::WrongWallet
                                             : ChainError::CryptoFailure;
    }

    uint8_t preimage[kQrlPreimageSize];
    SensitiveValue<uint8_t[kSha256Size]> digest;
    size_t preimage_size = 0;
    const bool built = build_preimage(request, sender_bytes, preimage,
                                      sizeof(preimage), &preimage_size);
    secure_zero(sender_bytes, sizeof(sender_bytes));
    const bool hashed = built && crypto_sha256(preimage, preimage_size, digest.get());
    secure_zero(preimage, sizeof(preimage));
    if (!hashed)
      return ChainError::CryptoFailure;

    const size_t signature_size = qrl_xmss_signature_size(kQrlDefaultHeight);
    const size_t needed = signature_size + kSha256Size + kQrlPublicKeySize;
    if (capacity < needed)
      return ChainError::BufferTooSmall;

    QrlOtsAccount account(*port, public_key.get());
    // A blank journal is bound to index zero here and nowhere else. The custody
    // layer must treat a blank journal on a funded account as a recovery event:
    // this path cannot tell a fresh account from a wiped one.
    QrlOtsError ots = account.bind();
    uint32_t leaf = 0;
    if (ots == QrlOtsError::Ok)
      ots = account.next_index(&leaf);
    if (ots != QrlOtsError::Ok)
      return map_ots_error(ots);

    const QrlOtsPort ots_port = account.port();
    size_t written = signature_size;
    const QrlSignError signed_error = qrl_xmss_sign_digest(
        qrl_seed.get(), public_key.get(), leaf, digest.get(), ots_port, out,
        &written);
    // qrl_xmss_sign_digest() verifies the signature it built against public_key
    // before returning, so a produced signature is known good.
    if (signed_error != QrlSignError::Ok)
    {
      return signed_error == QrlSignError::Aborted ? ChainError::CryptoFailure
                                                   : ChainError::StorageUnavailable;
    }
    if (written != signature_size)
    {
      secure_zero(out, capacity);
      return ChainError::CryptoFailure;
    }
    memcpy(out + signature_size, digest.get(), kSha256Size);
    memcpy(out + signature_size + kSha256Size, public_key.get(), kQrlPublicKeySize);
    *in_out_size = needed;
    return ChainError::Ok;
  }

  bool run_qrl_transaction_self_tests()
  {
    // A host-side store with the same two-slot behaviour as the device: the
    // journal writes, reads back and refuses to rewind.
    class TestPort : public QrlOtsSlotPort
    {
    public:
      bool read_slot(const uint8_t tag[kQrlOtsTagSize], uint8_t slot,
                     uint8_t *out, size_t size) override
      {
        if (tag == nullptr || out == nullptr || slot >= kQrlOtsSlotCount ||
            size != kQrlOtsSlotSize || !written[slot] ||
            memcmp(stored_tag[slot], tag, kQrlOtsTagSize) != 0)
        {
          return false;
        }
        memcpy(out, stored[slot], size);
        return true;
      }
      bool write_slot(const uint8_t tag[kQrlOtsTagSize], uint8_t slot,
                      const uint8_t *data, size_t size) override
      {
        if (tag == nullptr || data == nullptr || slot >= kQrlOtsSlotCount ||
            size != kQrlOtsSlotSize || fail)
        {
          return false;
        }
        memcpy(stored[slot], data, size);
        memcpy(stored_tag[slot], tag, kQrlOtsTagSize);
        written[slot] = true;
        return true;
      }
      uint8_t stored[kQrlOtsSlotCount][kQrlOtsSlotSize] = {};
      uint8_t stored_tag[kQrlOtsSlotCount][kQrlOtsTagSize] = {};
      bool written[kQrlOtsSlotCount] = {};
      bool fail = false;
    };

    // Build a structurally valid recipient: descriptor, body and checksum.
    uint8_t recipient[kQrlAddressBinarySize];
    recipient[0] = 0x02;
    recipient[1] = kQrlDefaultHeight >> 1;
    recipient[2] = 0x00;
    for (size_t index = 3; index < 35; ++index)
    {
      recipient[index] = static_cast<uint8_t>(0x40 + index);
    }
    uint8_t checksum[kSha256Size];
    bool passed = crypto_sha256(recipient, 35, checksum);
    memcpy(recipient + 35, checksum + kSha256Size - 4, 4);
    passed = passed && qrl_address_bytes_valid(recipient);

    // "QRL1" | flags | fee=1000 | nonce=7 | message "hi" | 2 outputs
    const uint8_t message[2] = {'h', 'i'};
    uint8_t payload[kQrlPayloadFixedSize + sizeof(message) + 1 +
                    2 * (kQrlAddressBinarySize + 8)] = {};
    memcpy(payload, "QRL1", 4);
    payload[4] = 0x00;
    write_be64(1000, payload + 5);
    payload[13] = 0;
    payload[14] = 0;
    payload[15] = 0;
    payload[16] = 7;
    payload[17] = 0;
    payload[18] = static_cast<uint8_t>(sizeof(message));
    memcpy(payload + 19, message, sizeof(message));
    size_t offset = 19 + sizeof(message);
    payload[offset++] = 2;
    memcpy(payload + offset, recipient, kQrlAddressBinarySize);
    offset += kQrlAddressBinarySize;
    write_be64(250000000, payload + offset);
    offset += 8;
    memcpy(payload + offset, recipient, kQrlAddressBinarySize);
    offset += kQrlAddressBinarySize;
    write_be64(750000000, payload + offset);
    offset += 8;
    const size_t payload_size = offset;

    // The preimage layout is pinned against qrllib's TransferTransaction: sender,
    // fee, message, then every (address, amount) pair, all big-endian.
    uint8_t sender[kQrlAddressBinarySize];
    memcpy(sender, recipient, sizeof(sender));
    uint8_t preimage[kQrlPreimageSize];
    memcpy(preimage, sender, kQrlAddressBinarySize);
    write_be64(1000, preimage + kQrlAddressBinarySize);
    memcpy(preimage + kQrlAddressBinarySize + 8, message, sizeof(message));
    size_t cursor = kQrlAddressBinarySize + 8 + sizeof(message);
    for (size_t index = 0; index < 2; ++index)
    {
      memcpy(preimage + cursor, recipient, kQrlAddressBinarySize);
      cursor += kQrlAddressBinarySize;
      write_be64(index == 0 ? 250000000 : 750000000, preimage + cursor);
      cursor += 8;
    }
    uint8_t expected_digest[kSha256Size];
    passed = passed && crypto_sha256(preimage, cursor, expected_digest);

    char sender_text[kQrlAddressTextSize];
    {
      uint8_t bytes[kQrlAddressBinarySize];
      memcpy(bytes, sender, sizeof(bytes));
      char hex[2 * kQrlAddressBinarySize + 1];
      chain_hex(bytes, sizeof(bytes), hex, sizeof(hex));
      snprintf(sender_text, sizeof(sender_text), "Q%s", hex);
      uint8_t decoded[kQrlAddressBinarySize];
      passed = passed && qrl_address_decode(sender_text, decoded) &&
               chain_constant_time_equal(decoded, bytes, sizeof(bytes));
    }

    ChainReview review;
    uint8_t digest[kSha256Size];
    passed = passed &&
             qrl_review_payload(payload, payload_size, sender_text, &review, digest) ==
                 ChainError::Ok &&
             chain_constant_time_equal(digest, expected_digest, kSha256Size) &&
             strcmp(review.symbol, "QRL") == 0 &&
             strcmp(review.amount, "10.0 QRL") == 0 &&
             strcmp(review.fee, "0.00001 QRL") == 0 &&
             strstr(review.extra, "NONCE 7") != nullptr &&
             strstr(review.extra, "OUTPUTS 2") != nullptr;

    // Mutations that must be refused before any signature exists.
    {
      uint8_t copy[kChainMaxPayload];
      ChainReview ignored;
      uint8_t ignored_digest[kSha256Size];
      // Changing an amount must change the digest: the amount really is signed.
      memcpy(copy, payload, payload_size);
      copy[payload_size - 1] ^= 0x01;
      passed = passed && qrl_review_payload(copy, payload_size, sender_text, &ignored, ignored_digest) == ChainError::Ok &&
               !chain_constant_time_equal(ignored_digest, expected_digest,
                                          kSha256Size);
      // Corrupt the first recipient byte: its checksum no longer matches.
      memcpy(copy, payload, payload_size);
      copy[19 + sizeof(message) + 1 + 5] ^= 0x80;
      passed = passed && qrl_review_payload(copy, payload_size, sender_text,
                                            &ignored, ignored_digest) ==
                             ChainError::Malformed;
      // Zero amount.
      memcpy(copy, payload, payload_size);
      memset(copy + 19 + sizeof(message) + 1 + kQrlAddressBinarySize, 0, 8);
      passed = passed && qrl_review_payload(copy, payload_size, sender_text,
                                            &ignored, ignored_digest) ==
                             ChainError::InvalidAmount;
      // Truncated payload.
      passed = passed && qrl_review_payload(copy, payload_size - 1, sender_text,
                                            &ignored, ignored_digest) !=
                             ChainError::Ok;
      // A sender that is not a QRL address.
      passed = passed && qrl_review_payload(payload, payload_size,
                                            "Qnot-an-address", &ignored,
                                            ignored_digest) ==
                             ChainError::WrongWallet;
    }

    // End-to-end signing against a real derived account (one full tree build per
    // call, so this runs at the default height only once).
    uint8_t seed[kSeedSize];
    for (size_t index = 0; index < sizeof(seed); ++index)
    {
      seed[index] = static_cast<uint8_t>(index * 5 + 1);
    }
    uint8_t qrl_seed[kQrlSeedSize];
    uint8_t public_key[kQrlPublicKeySize];
    bool account_ok = qrl_seed_from_bip39(seed, 0, qrl_seed) == WalletError::Ok &&
                      qrl_xmss_public_key(qrl_seed, kQrlDefaultHeight, public_key) ==
                          WalletError::Ok;
    secure_zero(qrl_seed, sizeof(qrl_seed));
    if (account_ok)
    {
      char account_text[kQrlAddressTextSize];
      account_ok = qrl_address_from_public_key(public_key, account_text,
                                               sizeof(account_text)) == WalletError::Ok;
      uint8_t owned[kQrlAddressBinarySize];
      account_ok = account_ok && qrl_address_decode(account_text, owned);
      if (account_ok)
      {
        uint8_t signed_payload[kChainMaxPayload];
        memcpy(signed_payload, payload, payload_size);
        memcpy(signed_payload + 19 + sizeof(message) + 1, owned, kQrlAddressBinarySize);
        memcpy(signed_payload + 19 + sizeof(message) + 1 + kQrlAddressBinarySize + 8,
               owned, kQrlAddressBinarySize);
        ChainReview owned_review;
        uint8_t owned_digest[kSha256Size];
        account_ok = qrl_review_payload(signed_payload, payload_size, account_text,
                                        &owned_review, owned_digest) == ChainError::Ok;
        uint8_t signed_data[kQrlMaxSignedSize];
        TestPort port;
        size_t signed_size = sizeof(signed_data);
        const ChainError first = qrl_sign_payload(
            &port, signed_payload, payload_size, account_text, seed, 0, signed_data,
            &signed_size);
        const size_t signature_size = qrl_xmss_signature_size(kQrlDefaultHeight);
        passed = passed && account_ok && first == ChainError::Ok &&
                 signed_size == signature_size + kSha256Size + kQrlPublicKeySize &&
                 chain_constant_time_equal(signed_data + signature_size, owned_digest,
                                           kSha256Size) &&
                 memcmp(signed_data + signature_size + kSha256Size, public_key,
                        kQrlPublicKeySize) == 0 &&
                 qrl_xmss_verify_digest(public_key, owned_digest, signed_data,
                                        signature_size);
        if (first == ChainError::Ok)
        {
          uint8_t second[kQrlMaxSignedSize];
          size_t second_size = sizeof(second);
          passed = passed && qrl_sign_payload(&port, signed_payload, payload_size, account_text, seed, 0, second, &second_size) == ChainError::Ok &&
                   second_size == signed_size &&
                   ((second[0] << 24) | (second[1] << 16) | (second[2] << 8) |
                    second[3]) == 1 &&
                   qrl_xmss_verify_digest(public_key, owned_digest, second,
                                          signature_size);
          secure_zero(second, sizeof(second));
          // A store that cannot persist must not release a signature.
          port.fail = true;
          size_t refused_size = sizeof(second);
          passed = passed &&
                   qrl_sign_payload(&port, signed_payload, payload_size, account_text,
                                    seed, 0, second, &refused_size) ==
                       ChainError::StorageUnavailable &&
                   refused_size == 0;
          port.fail = false;
        }
        secure_zero(signed_data, sizeof(signed_data));
        secure_zero(signed_payload, sizeof(signed_payload));
      }
    }
    secure_zero(seed, sizeof(seed));
    secure_zero(public_key, sizeof(public_key));
    secure_zero(preimage, sizeof(preimage));
    secure_zero(checksum, sizeof(checksum));
    return passed;
  }

} // namespace hexwallet
