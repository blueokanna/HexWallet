#ifndef HEXWALLET_TEXT_INPUT_H
#define HEXWALLET_TEXT_INPUT_H
#include <stddef.h>
#include <stdint.h>

namespace hexwallet {
enum class TextInputError : uint8_t { Ok, Full, InvalidUtf8, UnsupportedCharacter, CompositionPending, NoCandidates };
// One editor owns one bounded buffer. UI labels use only a separate preview;
// text never enters LVGL's reallocating textarea/history buffers.
class WalletTextInput final {
 public:
  static constexpr size_t kCapacity = 256;
  WalletTextInput() = default;
  ~WalletTextInput() { clear(); }
  WalletTextInput(const WalletTextInput &) = delete;
  WalletTextInput &operator=(const WalletTextInput &) = delete;
  void clear();
  void begin(size_t limit, bool secret);
  TextInputError insert(const char *text, size_t size);
  TextInputError compose(char letter);
  TextInputError choose(size_t candidate);
  void backspace();
  const char *text() const { return text_; }
  size_t size() const { return size_; }
  const char *composition() const { return composition_; }
  size_t candidate_count() const;
  bool candidate(size_t index, char out[4]) const;
  const char *preview();
 private:
  char text_[kCapacity + 1] = {};
  char composition_[8] = {};
  char preview_[kCapacity + 1] = {};
  size_t size_ = 0, limit_ = kCapacity, composing_ = 0;
  bool secret_ = true;
};
}
#endif
