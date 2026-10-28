#ifndef HEXWALLET_MASCOT_H
#define HEXWALLET_MASCOT_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet
{

  enum class MascotMood : uint8_t
  {
    Calm = 0,
    Happy,
    Alert,
    Sleep,
    Hungry,
    Shy,
  };

  const char *mascot_mood_name(MascotMood mood);

  enum class MascotReminder : uint8_t
  {
    None = 0,
    Hungry,
    BackupDue,
    LowBattery,
    PhoneNotLinked,
  };

  const char *mascot_reminder_text(MascotReminder reminder);

  // Inputs the firmware already has; the companion only interprets them.
  struct MascotInputs
  {
    bool backup_due;
    bool phone_linked;
    uint16_t battery_mv;
  };

  struct MascotStats
  {
    uint16_t approvals;
    uint16_t rejections;
    uint16_t pets;
    uint16_t feeds;
    uint16_t plays;
  };

  struct MascotSnapshot
  {
    MascotMood mood;
    MascotReminder reminder;
    uint8_t level;
    uint8_t hunger;   // 0 = full, 100 = starving
    uint8_t energy;   // 0 = exhausted, 100 = wide awake
    uint8_t bond;     // points inside the current level
    uint8_t bond_max; // points needed for the next level
    MascotStats stats;
  };

  // Persisted fields: bounded, fixed size, no timestamps.
  struct MascotPersisted
  {
    uint32_t magic;
    uint16_t approvals;
    uint16_t rejections;
    uint16_t pets;
    uint16_t feeds;
    uint16_t plays;
    uint16_t bond_points;
  };

  constexpr uint32_t kMascotPersistMagic = 0x4D415343UL; // "MASC"
  constexpr uint16_t kMascotPointsPerLevel = 25;
  constexpr uint8_t kMascotMaxLevel = 9;
  constexpr uint32_t kMascotSleepAfterMs = 5UL * 60UL * 1000UL;
  constexpr uint32_t kMascotHungryAfterMs = 30UL * 60UL * 1000UL;
  constexpr uint32_t kMascotStarvingAfterMs = 90UL * 60UL * 1000UL;
  constexpr uint32_t kMascotReactionMs = 20UL * 1000UL;
  constexpr uint32_t kMascotFrameMinMs = 30UL * 1000UL;
  constexpr uint32_t kMascotActionCooldownMs = 2UL * 1000UL;

  // Storage hooks supplied by the platform (NVS on device, a fake in tests).
  struct MascotStore
  {
    void *context;
    bool (*load)(void *context, MascotPersisted *out);
    bool (*save)(void *context, const MascotPersisted &value);
  };

  void mascot_bind_store(const MascotStore &store);

#if defined(ARDUINO)
// Binds the NVS-backed store and restores counters. Returns false when nothing
// was stored yet (first boot), which is not an error.
bool mascot_nvs_begin();
#endif
  bool mascot_load();
  bool mascot_save();

  void mascot_note_approval(uint32_t now_ms);
  void mascot_note_rejection(uint32_t now_ms);
  bool mascot_pet(uint32_t now_ms);
  bool mascot_feed(uint32_t now_ms);
  bool mascot_play(uint32_t now_ms);
  void mascot_note_activity(uint32_t now_ms);

  MascotSnapshot mascot_snapshot(const MascotInputs &inputs, uint32_t now_ms);

  // True at most once per kMascotFrameMinMs and only when something changed.
  bool mascot_take_frame_request(uint32_t now_ms);

  // Frame index to draw for the current mood; alternates for the idle blink.
  uint8_t mascot_frame_index(uint32_t now_ms);

  void mascot_reset();

  bool run_mascot_self_tests();

}

#endif
