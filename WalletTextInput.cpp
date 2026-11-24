#include "WalletTextInput.h"
#include <string.h>

namespace hexwallet {
namespace {
#include "src/generated/PinyinDictionary.inc"
void erase(void *memory, size_t size) {
  volatile uint8_t *bytes = static_cast<volatile uint8_t *>(memory);
  while (size--) *bytes++ = 0;
}
const char *candidates(const char *syllable) {
  size_t lo = 0, hi = sizeof(kPinyinDictionary) / sizeof(kPinyinDictionary[0]);
  while (lo < hi) {
    const size_t mid = lo + (hi - lo) / 2;
    const int order = strcmp(syllable, kPinyinDictionary[mid].syllable);
    if (!order) return kPinyinDictionary[mid].characters;
    if (order < 0) hi = mid; else lo = mid + 1;
  }
  return "";
}
}
void WalletTextInput::clear() {
  erase(text_, sizeof(text_)); erase(composition_, sizeof(composition_)); erase(preview_, sizeof(preview_));
  size_ = composing_ = 0;
  limit_ = kCapacity;
  secret_ = true;
}
void WalletTextInput::begin(size_t limit, bool secret) {
  clear();
  limit_ = limit <= kCapacity ? limit : kCapacity;
  secret_ = secret;
}
TextInputError WalletTextInput::insert(const char *text, size_t size) {
  if (!text) return TextInputError::InvalidUtf8;
  if (size > limit_ - size_) return TextInputError::Full;
  size_t i = 0;
  while (i < size) {
    uint32_t code = static_cast<uint8_t>(text[i++]), minimum = 0;
    unsigned tail = 0;
    if (code >= 0xc2 && code <= 0xdf) { tail = 1; minimum = 0x80; code &= 31; }
    else if (code >= 0xe0 && code <= 0xef) { tail = 2; minimum = 0x800; code &= 15; }
    else if (code >= 0xf0 && code <= 0xf4) { tail = 3; minimum = 0x10000; code &= 7; }
    else if (code >= 0x80) return TextInputError::InvalidUtf8;
    if (tail > size - i) return TextInputError::InvalidUtf8;
    while (tail--) {
      const auto next = static_cast<uint8_t>(text[i++]);
      if ((next & 0xc0) != 0x80) return TextInputError::InvalidUtf8;
      code = (code << 6) | (next & 63);
    }
    if (code < minimum || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return TextInputError::InvalidUtf8;
    if (code < 32 || (code >= 0x7f && code <= 0x9f) ||
        (code >= 0x200b && code <= 0x200f) || (code >= 0x202a && code <= 0x202e) ||
        (code >= 0x2060 && code <= 0x206f) || code == 0xfeff) return TextInputError::UnsupportedCharacter;
  }
  memcpy(text_ + size_, text, size);
  size_ += size;
  text_[size_] = 0;
  return TextInputError::Ok;
}
TextInputError WalletTextInput::compose(char letter) {
  if (letter < 'a' || letter > 'z') return TextInputError::UnsupportedCharacter;
  if (composing_ == sizeof(composition_) - 1) return TextInputError::Full;
  composition_[composing_++] = letter;
  return TextInputError::Ok;
}
size_t WalletTextInput::candidate_count() const { return strlen(candidates(composition_)) / 3; }
bool WalletTextInput::candidate(size_t index, char out[4]) const {
  if (!out) return false;
  memset(out, 0, 4);
  if (index >= candidate_count()) return false;
  memcpy(out, candidates(composition_) + index * 3, 3);
  return true;
}
TextInputError WalletTextInput::choose(size_t index) {
  char out[4];
  if (!candidate(index, out)) return TextInputError::NoCandidates;
  const auto result = insert(out, 3);
  if (result == TextInputError::Ok) {
    erase(composition_, sizeof(composition_)); composing_ = 0;
  }
  erase(out, sizeof(out));
  return result;
}
void WalletTextInput::backspace() {
  if (composing_) { composition_[--composing_] = 0; return; }
  if (!size_) return;
  size_t begin = size_ - 1;
  while (begin && (static_cast<uint8_t>(text_[begin]) & 0xc0) == 0x80) --begin;
  erase(text_ + begin, size_ - begin);
  size_ = begin;
}
const char *WalletTextInput::preview() {
  erase(preview_, sizeof(preview_));
  if (secret_) {
    size_t count = 0;
    for (size_t i = 0; i < size_; ++i) if ((static_cast<uint8_t>(text_[i]) & 0xc0) != 0x80) preview_[count++] = '*';
  } else memcpy(preview_, text_, size_);
  return preview_;
}
}
