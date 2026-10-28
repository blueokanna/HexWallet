#include "Mascot.h"

#if defined(ARDUINO)

#include <Preferences.h>

namespace hexwallet {

namespace {

// One NVS blob, fixed size, with the magic checked on load. Keeping the whole
// companion in a single key means a partial write can never leave the counters
// and the bond out of step with each other.
constexpr const char *kNamespace = "hexpet";
constexpr const char *kKey = "state";

bool nvs_load(void *, MascotPersisted *out) {
  if (out == nullptr) return false;
  Preferences preferences;
  if (!preferences.begin(kNamespace, true)) return false;
  bool ok = false;
  if (preferences.getBytesLength(kKey) == sizeof(MascotPersisted)) {
    ok = preferences.getBytes(kKey, out, sizeof(MascotPersisted)) ==
         sizeof(MascotPersisted);
  }
  preferences.end();
  return ok;
}

bool nvs_save(void *, const MascotPersisted &value) {
  Preferences preferences;
  if (!preferences.begin(kNamespace, false)) return false;
  const bool ok = preferences.putBytes(kKey, &value, sizeof(value)) ==
                  sizeof(value);
  preferences.end();
  return ok;
}

}  // namespace

bool mascot_nvs_begin() {
  const MascotStore store = {nullptr, nvs_load, nvs_save};
  mascot_bind_store(store);
  return mascot_load();
}

}  // namespace hexwallet

#endif  // ARDUINO
