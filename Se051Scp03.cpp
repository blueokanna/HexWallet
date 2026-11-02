#include "Se051Scp03.h"
#include <string.h>
#include "CryptoPrimitives.h"
#include "SecureElementPort.h"
#include "WalletSecurity.h"

namespace hexwallet
{
  namespace
  {
    bool reject(Scp03Session *s)
    {
      scp03_reset(s);
      return false;
    }
    bool derive(const uint8_t key[16], uint8_t label, uint16_t bits,
                const uint8_t context[16], uint8_t out[16])
    {
      // GP Amendment D 4.1.5: label(12) | separator | L(2) | i | context.
      uint8_t input[32] = {};
      input[11] = label;
      input[13] = static_cast<uint8_t>(bits >> 8);
      input[14] = static_cast<uint8_t>(bits);
      input[15] = 1;
      memcpy(input + 16, context, 16);
      const bool ok = aes128_cmac(key, input, sizeof(input), out);
      secure_zero(input, sizeof(input));
      return ok;
    }
    bool proof(const Scp03Session &s, uint8_t label, const uint8_t context[16],
               uint8_t out[8])
    {
      if (out == nullptr)
        return false;
      secure_zero(out, 8);
      if (context == nullptr || s.phase == Scp03Phase::Empty ||
          !crypto_constant_time_equal(context, s.context, 16))
        return false;
      uint8_t full[16] = {};
      const bool ok = derive(s.s_mac, label, 64, context, full);
      if (ok)
        memcpy(out, full, 8);
      secure_zero(full, sizeof(full));
      return ok;
    }
    void iv(const Scp03Session &s, bool response, uint8_t out[16])
    {
      uint8_t counter[16] = {};
      counter[0] = response ? 0x80 : 0;
      counter[12] = static_cast<uint8_t>(s.commands >> 24);
      counter[13] = static_cast<uint8_t>(s.commands >> 16);
      counter[14] = static_cast<uint8_t>(s.commands >> 8);
      counter[15] = static_cast<uint8_t>(s.commands);
      Aes128Schedule schedule;
      aes128_expand_key(s.s_enc, &schedule);
      aes128_encrypt_block(schedule, counter, out);
      secure_zero(&schedule, sizeof(schedule));
      secure_zero(counter, sizeof(counter));
    }
    void cbc(const Scp03Session &s, uint8_t *data, size_t size, bool decrypt)
    {
      Aes128Schedule schedule;
      aes128_expand_key(s.s_enc, &schedule);
      uint8_t chain[16], block[16], next[16];
      iv(s, decrypt, chain);
      for (size_t offset = 0; offset < size; offset += 16)
      {
        if (decrypt)
        {
          memcpy(next, data + offset, 16);
          aes128_decrypt_block(schedule, next, block);
          for (size_t i = 0; i < 16; ++i)
            data[offset + i] = block[i] ^ chain[i];
          memcpy(chain, next, 16);
        }
        else
        {
          for (size_t i = 0; i < 16; ++i)
            block[i] = data[offset + i] ^ chain[i];
          aes128_encrypt_block(schedule, block, chain);
          memcpy(data + offset, chain, 16);
        }
      }
      secure_zero(&schedule, sizeof(schedule));
      secure_zero(chain, sizeof(chain));
      secure_zero(block, sizeof(block));
      secure_zero(next, sizeof(next));
    }
    bool command_mac(Scp03Session *s, uint8_t *apdu, size_t size)
    {
      uint8_t input[16 + 5 + 240] = {}, mac[16] = {};
      if (size > sizeof(input) - 16)
        return false;
      memcpy(input, s->command_chaining, 16);
      memcpy(input + 16, apdu, size);
      // CMAC owns subkey selection and padding. Do not pre-pad its input.
      const bool ok = aes128_cmac(s->s_mac, input, size + 16, mac);
      if (ok)
      {
        memcpy(apdu + size, mac, 8);
        memcpy(s->command_chaining, mac, 16);
      }
      secure_zero(input, sizeof(input));
      secure_zero(mac, sizeof(mac));
      return ok;
    }
    bool matches(const uint8_t *actual, size_t size, const char *hex)
    {
      uint8_t difference = 0;
      for (size_t i = 0; i < size; ++i)
      {
        uint8_t byte = 0;
        for (size_t n = 0; n < 2; ++n)
        {
          const char c = *hex++;
          if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
          byte = static_cast<uint8_t>((byte << 4) | (c <= '9' ? c - '0' : c - 'a' + 10));
        }
        difference |= byte ^ actual[i];
      }
      return *hex == '\0' && difference == 0;
    }
  }

  void scp03_reset(Scp03Session *s)
  {
    if (s != nullptr)
      secure_zero(s, sizeof(*s));
  }
  bool scp03_authenticated(const Scp03Session &s)
  {
    return s.phase == Scp03Phase::Established || s.phase == Scp03Phase::CommandPending;
  }
  bool scp03_derive_session_keys(const Scp03StaticKeys &keys,
                                 const uint8_t context[16], Scp03Session *s)
  {
    if (s == nullptr)
      return false;
    scp03_reset(s);
    if (context == nullptr)
      return false;
    memcpy(s->context, context, 16);
    if (!derive(keys.enc, 4, 128, context, s->s_enc) ||
        !derive(keys.mac, 6, 128, context, s->s_mac) ||
        !derive(keys.mac, 7, 128, context, s->s_rmac))
      return reject(s);
    s->phase = Scp03Phase::KeysDerived;
    return true;
  }
  bool scp03_card_cryptogram(const Scp03Session &s, const uint8_t context[16], uint8_t out[8])
  {
    return proof(s, 0, context, out);
  }
  bool scp03_host_cryptogram(const Scp03Session &s, const uint8_t context[16], uint8_t out[8])
  {
    if (s.phase != Scp03Phase::CardVerified)
    {
      if (out != nullptr)
        secure_zero(out, 8);
      return false;
    }
    return proof(s, 1, context, out);
  }
  bool scp03_verify_card(Scp03Session *s, const uint8_t received[8])
  {
    if (s == nullptr)
      return false;
    if (s->phase != Scp03Phase::KeysDerived || received == nullptr)
      return reject(s);
    uint8_t expected[8] = {};
    const bool ok = scp03_card_cryptogram(*s, s->context, expected) &&
                    crypto_constant_time_equal(expected, received, 8);
    secure_zero(expected, sizeof(expected));
    if (!ok)
      return reject(s);
    s->phase = Scp03Phase::CardVerified;
    return true;
  }
  bool scp03_external_authenticate(Scp03Session *s, uint8_t *out,
                                   size_t capacity, size_t *out_size)
  {
    if (out_size != nullptr)
      *out_size = 0;
    if (s == nullptr)
      return false;
    if (out == nullptr || out_size == nullptr || capacity < 21 ||
        s->phase != Scp03Phase::CardVerified)
      return reject(s);
    const uint8_t header[] = {0x84, 0x82, 0x33, 0x00, 0x10};
    memcpy(out, header, sizeof(header));
    if (!scp03_host_cryptogram(*s, s->context, out + 5) || !command_mac(s, out, 13))
    {
      secure_zero(out, 21);
      return reject(s);
    }
    *out_size = 21;
    s->phase = Scp03Phase::ExternalAuthenticatePending;
    return true;
  }
  bool scp03_finish_authentication(Scp03Session *s, const uint8_t *response, size_t size)
  {
    if (s == nullptr)
      return false;
    if (s->phase != Scp03Phase::ExternalAuthenticatePending || response == nullptr ||
        size != 2 || response[0] != 0x90 || response[1] != 0x00)
      return reject(s);
    s->phase = Scp03Phase::Established;
    return true;
  }
  bool scp03_wrap_command(Scp03Session *s, uint8_t cla, uint8_t ins,
                          uint8_t p1, uint8_t p2, const uint8_t *data,
                          size_t size, bool encrypt_data, bool expect_response,
                          uint8_t *out, size_t capacity, size_t *out_size)
  {
    if (out_size != nullptr)
      *out_size = 0;
    if (s == nullptr)
      return false;
    if (s->phase != Scp03Phase::Established || !encrypt_data || cla != 0x80 ||
        out == nullptr || out_size == nullptr || (size != 0 && data == nullptr) ||
        size > kScp03MaxCommandData || s->commands == UINT32_MAX)
      return reject(s);
    const size_t body = size == 0 ? 0 : (size / 16 + 1) * 16;
    const size_t total = 5 + body + 8 + (expect_response ? 1 : 0);
    if (capacity < total)
      return reject(s);
    if (size != 0)
      memmove(out + 5, data, size);
    out[0] = 0x84;
    out[1] = ins;
    out[2] = p1;
    out[3] = p2;
    out[4] = static_cast<uint8_t>(body + 8);
    ++s->commands;
    if (size != 0)
    {
      out[5 + size] = 0x80;
      memset(out + 6 + size, 0, body - size - 1);
      cbc(*s, out + 5, body, false);
    }
    if (!command_mac(s, out, 5 + body))
    {
      secure_zero(out, total);
      return reject(s);
    }
    if (expect_response)
      out[total - 1] = 0;
    *out_size = total;
    s->phase = Scp03Phase::CommandPending;
    return true;
  }
  bool scp03_unwrap_response(Scp03Session *s, uint8_t *response,
                             size_t *response_size, bool encrypted, uint16_t *status)
  {
    if (status != nullptr)
      *status = 0;
    const size_t total = response_size == nullptr ? 0 : *response_size;
    if (response_size != nullptr)
      *response_size = 0;
    if (s == nullptr)
      return false;
    if (s->phase != Scp03Phase::CommandPending || response == nullptr ||
        response_size == nullptr || !encrypted || total < 10 ||
        total > kScp03MaxResponseData + 10)
      return reject(s);
    const size_t ciphertext = total - 10;
    const uint16_t sw = static_cast<uint16_t>((response[total - 2] << 8) | response[total - 1]);
    if ((sw != 0x9000 && (sw >> 8) != 0x62 && (sw >> 8) != 0x63) ||
        ciphertext % 16 != 0)
      return reject(s);
    uint8_t input[16 + kScp03MaxResponseData + 2] = {}, expected[16] = {};
    memcpy(input, s->command_chaining, 16);
    memcpy(input + 16, response, ciphertext);
    input[16 + ciphertext] = response[total - 2];
    input[17 + ciphertext] = response[total - 1];
    const bool verified = aes128_cmac(s->s_rmac, input, 18 + ciphertext, expected) &&
                          crypto_constant_time_equal(expected, response + ciphertext, 8);
    secure_zero(input, sizeof(input));
    secure_zero(expected, sizeof(expected));
    if (!verified)
    {
      secure_zero(response, total);
      return reject(s);
    }
    size_t plain = ciphertext;
    if (ciphertext != 0)
    {
      cbc(*s, response, ciphertext, true);
      const size_t minimum = ciphertext - 16;
      while (plain > minimum && response[plain - 1] == 0)
        --plain;
      if (plain == minimum || response[plain - 1] != 0x80)
      {
        secure_zero(response, total);
        return reject(s);
      }
      --plain;
    }
    secure_zero(response + plain, total - plain);
    *response_size = plain;
    if (status != nullptr)
      *status = sw;
    s->phase = Scp03Phase::Established;
    return true;
  }

  bool run_scp03_self_tests()
  {
    Scp03StaticKeys keys = {};
    memset(keys.enc, 0x0b, 16);
    memset(keys.mac, 0x1c, 16);
    const uint8_t context[16] = {1, 2, 3, 4, 5, 6, 7, 8, 17, 18, 19, 20, 21, 22, 23, 24};
    Scp03Session s = {};
    uint8_t proof_bytes[8] = {}, command[256] = {};
    size_t size = 77;
    bool ok = scp03_derive_session_keys(keys, context, &s) && !scp03_authenticated(s);
    ok = !scp03_host_cryptogram(s, context, proof_bytes) && ok;
    ok = scp03_card_cryptogram(s, context, proof_bytes) && scp03_verify_card(&s, proof_bytes) && ok;
    ok = scp03_external_authenticate(&s, command, sizeof(command), &size) && size == 21 && !scp03_authenticated(s) && ok;
    const uint8_t success[2] = {0x90, 0};
    ok = scp03_finish_authentication(&s, success, 2) && scp03_authenticated(s) && ok;
    ok = scp03_wrap_command(&s, 0x80, 0x14, 0, 0, nullptr, 0, true, false,
                            command, sizeof(command), &size) &&
         size == 13 && s.commands == 1 && ok;
    ok = !scp03_wrap_command(&s, 0x80, 0x14, 0, 0, nullptr, 0, true, false,
                             command, sizeof(command), &size) &&
         !scp03_authenticated(s) && size == 0 && ok;
    scp03_reset(&s);
    secure_zero(&keys, sizeof(keys));
    return ok;
  }
}
