#include "QrlOtsStore.h"

#include <string.h>

#include "CryptoPrimitives.h"

#if defined(ARDUINO)
#include <nvs.h>
#endif

namespace hexwallet {
namespace {

QrlOtsSlotPort *g_platform_port = nullptr;

#if defined(ARDUINO)

// One namespace, two keys per account, key length stays inside the NVS
// 15-character limit: 'q' + 12 hex digits of the account tag + slot digit.
constexpr const char *kQrlOtsNamespace = "qrlots";

void slot_key(const uint8_t tag[kQrlOtsTagSize], uint8_t slot, char out[16]) {
  static const char kHex[] = "0123456789abcdef";
  out[0] = 'q';
  for (size_t index = 0; index < 6; ++index) {
    out[1 + index * 2] = kHex[tag[index] >> 4];
    out[2 + index * 2] = kHex[tag[index] & 0x0f];
  }
  out[13] = static_cast<char>('0' + slot);
  out[14] = '\0';
}

class QrlOtsNvsPort : public QrlOtsSlotPort {
 public:
  bool read_slot(const uint8_t tag[kQrlOtsTagSize], uint8_t slot, uint8_t *out,
                 size_t size) override {
    if (tag == nullptr || out == nullptr || slot >= kQrlOtsSlotCount) return false;
    char key[16];
    slot_key(tag, slot, key);
    nvs_handle_t handle = 0;
    if (nvs_open(kQrlOtsNamespace, NVS_READONLY, &handle) != ESP_OK) return false;
    size_t length = size;
    const bool ok = nvs_get_blob(handle, key, out, &length) == ESP_OK &&
                    length == size;
    nvs_close(handle);
    return ok;
  }

  bool write_slot(const uint8_t tag[kQrlOtsTagSize], uint8_t slot,
                  const uint8_t *data, size_t size) override {
    if (tag == nullptr || data == nullptr || slot >= kQrlOtsSlotCount) return false;
    char key[16];
    slot_key(tag, slot, key);
    nvs_handle_t handle = 0;
    if (nvs_open(kQrlOtsNamespace, NVS_READWRITE, &handle) != ESP_OK) return false;
    // nvs_set_blob() only lands in flash after nvs_commit(); returning true
    // before that would let a signature outlive the index that authorises it.
    const bool ok = nvs_set_blob(handle, key, data, size) == ESP_OK &&
                    nvs_commit(handle) == ESP_OK;
    nvs_close(handle);
    return ok;
  }
};

#endif  // ARDUINO

}  // namespace

QrlOtsSlotPort *qrl_ots_platform_port() {
  if (g_platform_port != nullptr) return g_platform_port;
#if defined(ARDUINO)
  static QrlOtsNvsPort nvs_port;
  return &nvs_port;
#else
  return nullptr;
#endif
}

void qrl_ots_set_platform_port(QrlOtsSlotPort *port) { g_platform_port = port; }

QrlOtsAccount::QrlOtsAccount(QrlOtsSlotPort &port,
                             const uint8_t public_key[kQrlPublicKeySize])
    : port_(port) {
  memset(tag_, 0, sizeof(tag_));
  uint8_t digest[kSha256Size];
  if (public_key != nullptr && crypto_sha256(public_key, kQrlPublicKeySize, digest)) {
    memcpy(tag_, digest, kQrlOtsTagSize);
  }
  secure_zero(digest, sizeof(digest));
}

bool QrlOtsAccount::read_slot(uint8_t slot, QrlOtsRecord *out) {
  if (out == nullptr || slot >= kQrlOtsSlotCount) return false;
  uint8_t bytes[kQrlOtsSlotSize];
  if (!port_.read_slot(tag_, slot, bytes, sizeof(bytes))) return false;
  // The record layout is fixed and little-endian, so the bytes on flash are the
  // struct. Reading field by field would silently accept a host-endian image.
  memcpy(out, bytes, sizeof(bytes));
  secure_zero(bytes, sizeof(bytes));
  return true;
}

bool QrlOtsAccount::write_slot(uint8_t slot, const QrlOtsRecord &record) {
  if (slot >= kQrlOtsSlotCount) return false;
  uint8_t bytes[kQrlOtsSlotSize];
  memcpy(bytes, &record, sizeof(bytes));
  const bool ok = port_.write_slot(tag_, slot, bytes, sizeof(bytes));
  secure_zero(bytes, sizeof(bytes));
  return ok;
}

QrlOtsError QrlOtsAccount::bind() {
  uint32_t mark = 0;
  const QrlOtsError state = qrl_ots_high_water(*this, tag_, &mark);
  if (state == QrlOtsError::Ok) return QrlOtsError::Ok;
  // Only a provably blank journal may be bound. A foreign or unreadable record
  // means this account has history, and starting over would reuse leaves.
  if (state != QrlOtsError::Unknown) return state;
  return qrl_ots_initialise(*this, tag_);
}

QrlOtsError QrlOtsAccount::next_index(uint32_t *index) {
  if (index == nullptr) return QrlOtsError::InvalidArgument;
  return qrl_ots_high_water(*this, tag_, index);
}

bool QrlOtsAccount::port_read(void *context, const uint8_t key_id[32],
                              uint32_t *high_water) {
  (void)key_id;  // The account is already selected by the constructor.
  QrlOtsAccount *self = static_cast<QrlOtsAccount *>(context);
  if (self == nullptr) return false;
  return qrl_ots_high_water(*self, self->tag_, high_water) == QrlOtsError::Ok;
}

bool QrlOtsAccount::port_reserve(void *context, const uint8_t key_id[32],
                                 uint32_t expected, uint32_t next_high_water) {
  (void)key_id;
  QrlOtsAccount *self = static_cast<QrlOtsAccount *>(context);
  if (self == nullptr) return false;
  // The signer may only consume the leaf it was told about. A jump would skip
  // leaves without proof, so it is refused here rather than burned silently.
  if (next_high_water != expected + 1U) return false;
  uint32_t reserved = 0;
  if (qrl_ots_reserve(*self, self->tag_, &reserved) != QrlOtsError::Ok) return false;
  return reserved == expected;
}

QrlOtsPort QrlOtsAccount::port() {
  QrlOtsPort port = {};
  port.context = this;
  port.read = port_read;
  port.reserve = port_reserve;
  return port;
}

}  // namespace hexwallet
