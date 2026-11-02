#include "TotpAccounts.h"

#include <stdio.h>
#include <string.h>

#include "WalletSecurity.h"

namespace hexwallet
{
  namespace
  {

    int hex_digit(char c)
    {
      if (c >= '0' && c <= '9')
        return c - '0';
      if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
      if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
      return -1;
    }

    bool decode_component(const char *text, size_t size, char *out, size_t capacity)
    {
      size_t written = 0;
      for (size_t i = 0; i < size; ++i)
      {
        unsigned char c = static_cast<unsigned char>(text[i]);
        if (c == '%')
        {
          if (size - i < 3)
            return false;
          const int hi = hex_digit(text[i + 1]), lo = hex_digit(text[i + 2]);
          if (hi < 0 || lo < 0)
            return false;
          c = static_cast<unsigned char>((hi << 4) | lo);
          i += 2;
        }
        if (c < 0x20 || c > 0x7e || written + 1 >= capacity)
          return false;
        out[written++] = static_cast<char>(c);
      }
      out[written] = '\0';
      return true;
    }

    bool has_visible_text(const char *text)
    {
      while (*text == ' ')
        ++text;
      return *text != '\0';
    }

    bool parse_number(const char *text, uint32_t limit, uint32_t *out)
    {
      if (*text == '\0')
        return false;
      uint32_t value = 0;
      for (; *text != '\0'; ++text)
      {
        if (*text < '0' || *text > '9')
          return false;
        const uint32_t digit = static_cast<uint32_t>(*text - '0');
        if (value > (limit - digit) / 10U)
          return false;
        value = value * 10U + digit;
      }
      if (value == 0 || value > limit)
        return false;
      *out = value;
      return true;
    }

    struct ParsedAccount
    {
      TotpAccountInfo info = {};
      uint8_t secret[kTotpSecretMaxBytes] = {};
      size_t secret_size = 0;
      ~ParsedAccount() { secure_zero(this, sizeof(*this)); }
    };

    TotpError parse_uri(const char *uri, size_t size, ParsedAccount *parsed)
    {
      static const char prefix[] = "otpauth://totp/";
      if (uri == nullptr || size > kTotpUriMaxBytes || size <= sizeof(prefix) - 1)
        return TotpError::InvalidUri;
      if (memcmp(uri, prefix, sizeof(prefix) - 1) != 0)
        return TotpError::Unsupported;
      for (size_t i = 0; i < size; ++i)
      {
        const unsigned char c = static_cast<unsigned char>(uri[i]);
        if (c < 0x21 || c > 0x7e || c == '#')
          return TotpError::InvalidUri;
      }
      const size_t label_start = sizeof(prefix) - 1;
      size_t query = label_start;
      while (query < size && uri[query] != '?')
        ++query;
      if (query == size || query == label_start)
        return TotpError::InvalidUri;
      char label[sizeof(parsed->info.issuer) + sizeof(parsed->info.account)] = {};
      if (!decode_component(uri + label_start, query - label_start, label,
                            sizeof(label)))
        return TotpError::InvalidUri;
      char *account = label;
      char *colon = strchr(label, ':');
      if (colon != nullptr)
      {
        *colon = '\0';
        if (!has_visible_text(label) || strlen(label) >= sizeof(parsed->info.issuer))
          return TotpError::InvalidUri;
        memcpy(parsed->info.issuer, label, strlen(label) + 1);
        account = colon + 1;
        while (*account == ' ')
          ++account;
      }
      if (!has_visible_text(account) || strchr(account, ':') != nullptr ||
          strlen(account) >= sizeof(parsed->info.account))
        return TotpError::InvalidUri;
      memcpy(parsed->info.account, account, strlen(account) + 1);
      parsed->info.period = kTotpDefaultPeriod;
      parsed->info.digits = kTotpDefaultDigits;
      parsed->info.algorithm = TotpAlgorithm::Sha1;

      uint8_t seen = 0;
      size_t cursor = query + 1;
      if (cursor == size)
        return TotpError::InvalidUri;
      while (cursor < size)
      {
        size_t end = cursor;
        while (end < size && uri[end] != '&')
          ++end;
        size_t equals = cursor;
        while (equals < end && uri[equals] != '=')
          ++equals;
        if (equals == cursor || equals == end || equals + 1 == end)
          return TotpError::InvalidUri;
        char name[16] = {};
        struct Value
        {
          char text[kTotpBase32MaxChars + 1] = {};
          ~Value() { secure_zero(this, sizeof(*this)); }
        } value;
        if (!decode_component(uri + cursor, equals - cursor, name, sizeof(name)) ||
            !decode_component(uri + equals + 1, end - equals - 1, value.text,
                              sizeof(value.text)))
          return TotpError::InvalidUri;
        uint8_t bit = 0;
        if (strcmp(name, "secret") == 0)
          bit = 1;
        else if (strcmp(name, "issuer") == 0)
          bit = 2;
        else if (strcmp(name, "algorithm") == 0)
          bit = 4;
        else if (strcmp(name, "digits") == 0)
          bit = 8;
        else if (strcmp(name, "period") == 0)
          bit = 16;
        else
          return TotpError::Unsupported;
        if ((seen & bit) != 0)
          return TotpError::DuplicateParameter;
        seen |= bit;
        switch (bit)
        {
        case 1:
        {
          // Whitespace is useful for manual Base32 entry, not URI secrets.
          if (strchr(value.text, ' ') != nullptr)
            return TotpError::InvalidBase32;
          const TotpError result = totp_base32_decode(
              value.text, parsed->secret, sizeof(parsed->secret), &parsed->secret_size);
          if (result != TotpError::Ok)
            return result;
          break;
        }
        case 2:
          if (!has_visible_text(value.text) || strchr(value.text, ':') != nullptr ||
              strlen(value.text) >= sizeof(parsed->info.issuer))
            return TotpError::InvalidUri;
          if (parsed->info.issuer[0] != '\0' &&
              strcmp(parsed->info.issuer, value.text) != 0)
            return TotpError::IssuerMismatch;
          memcpy(parsed->info.issuer, value.text, strlen(value.text) + 1);
          break;
        case 4:
          if (strcmp(value.text, "SHA1") == 0)
            parsed->info.algorithm = TotpAlgorithm::Sha1;
          else if (strcmp(value.text, "SHA256") == 0)
            parsed->info.algorithm = TotpAlgorithm::Sha256;
          else if (strcmp(value.text, "SHA512") == 0)
            parsed->info.algorithm = TotpAlgorithm::Sha512;
          else
            return TotpError::Unsupported;
          break;
        case 8:
          if (strcmp(value.text, "6") == 0)
            parsed->info.digits = 6;
          else if (strcmp(value.text, "8") == 0)
            parsed->info.digits = 8;
          else
            return TotpError::Unsupported;
          break;
        case 16:
          if (!parse_number(value.text, 3600, &parsed->info.period))
            return TotpError::InvalidArgument;
          break;
        }
        if (end == size)
          break;
        cursor = end + 1;
        if (cursor == size)
          return TotpError::InvalidUri;
      }
      return (seen & 1) != 0 ? TotpError::Ok : TotpError::InvalidUri;
    }

  } // namespace

  TotpAccounts::TotpAccounts() { clear(); }
  TotpAccounts::~TotpAccounts() { clear(); }

  void TotpAccounts::clear() { secure_zero(entries_, sizeof(entries_)); }

  TotpError TotpAccounts::import_uri(const char *uri, size_t size, uint8_t *out_slot)
  {
    if (out_slot == nullptr)
      return TotpError::InvalidArgument;
    *out_slot = UINT8_MAX;
    ParsedAccount parsed;
    const TotpError error = parse_uri(uri, size, &parsed);
    if (error != TotpError::Ok)
      return error;
    uint8_t free_slot = UINT8_MAX;
    for (uint8_t i = 0; i < kTotpAccountLimit; ++i)
    {
      if (!entries_[i].occupied)
      {
        if (free_slot == UINT8_MAX)
          free_slot = i;
      }
      else if (strcmp(entries_[i].info.issuer, parsed.info.issuer) == 0 &&
               strcmp(entries_[i].info.account, parsed.info.account) == 0)
      {
        return TotpError::AccountExists;
      }
    }
    if (free_slot == UINT8_MAX)
      return TotpError::StorageFull;
    Entry &entry = entries_[free_slot];
    entry.info = parsed.info;
    memcpy(entry.secret, parsed.secret, parsed.secret_size);
    entry.secret_size = parsed.secret_size;
    entry.occupied = true;
    *out_slot = free_slot;
    return TotpError::Ok;
  }

  bool TotpAccounts::info(uint8_t slot, TotpAccountInfo *out) const
  {
    if (out == nullptr)
      return false;
    memset(out, 0, sizeof(*out));
    if (slot >= kTotpAccountLimit || !entries_[slot].occupied)
      return false;
    *out = entries_[slot].info;
    return true;
  }

  bool TotpAccounts::remove(uint8_t slot)
  {
    if (slot >= kTotpAccountLimit || !entries_[slot].occupied)
      return false;
    secure_zero(&entries_[slot], sizeof(entries_[slot]));
    return true;
  }

  TotpError TotpAccounts::generate(uint8_t slot, uint64_t now_ms,
                                   char out_code[kTotpCodeTextSize],
                                   uint32_t *out_remaining) const
  {
    if (out_code != nullptr)
      secure_zero(out_code, kTotpCodeTextSize);
    if (out_remaining != nullptr)
      *out_remaining = 0;
    if (out_code == nullptr || out_remaining == nullptr)
      return TotpError::InvalidArgument;
    if (slot >= kTotpAccountLimit || !entries_[slot].occupied)
      return TotpError::InvalidAccount;
    uint64_t now = 0;
    if (!totp_clock_unix(now_ms, &now))
      return TotpError::ClockNotSet;
    const Entry &entry = entries_[slot];
    uint32_t code = 0;
    const TotpError error = totp_generate_unix(entry.secret, entry.secret_size, now,
                                               entry.info.period, entry.info.digits, entry.info.algorithm, &code);
    if (error != TotpError::Ok)
      return error;
    snprintf(out_code, kTotpCodeTextSize, "%0*u", static_cast<int>(entry.info.digits),
             static_cast<unsigned>(code));
    secure_zero(&code, sizeof(code));
    *out_remaining = entry.info.period - static_cast<uint32_t>(now % entry.info.period);
    return TotpError::Ok;
  }

}
