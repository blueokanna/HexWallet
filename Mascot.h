#ifndef HEXWALLET_MASCOT_H
#define HEXWALLET_MASCOT_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// The companion: a chibi whale-girl that lives on the home screen.
//
// Personality first, rendering second. The engine decides *what she is doing*
// (mood + pose + animation frame); WalletUi.cpp turns that into LVGL shapes. No
// LVGL dependency here, so the whole behaviour is testable on the host, and the
// renderer can change without touching a single rule.
//
// Deliberate limits, because this runs on a wallet:
//   * she never touches keys or the seed, and never changes a signing decision -
//     she only reacts to decisions that already happened;
//   * she never refreshes the panel on her own schedule. Frames are event driven
//     and rate limited; an e-paper update costs hundreds of milliseconds even in
//     partial mode, and an animated pet must not slow a signing flow down;
//   * persistence is counters only. millis() timestamps mean nothing across a
//     reboot, so hunger restarts at "just fed" and mood is always derived.

enum class MascotMood : uint8_t {
  Calm = 0,
  Happy,
  Alert,
  Angry,
  Eating,
  Excited,
  Working,
  Sleep,
  Shy,
};

constexpr uint8_t kMascotMoodCount = 9;

const char *mascot_mood_name(MascotMood mood);

// What to draw. The renderer reads this; nothing else.
struct MascotPose {
  uint8_t eyes;  // 0 open, 1 closed, 2 happy arc, 3 angry
  uint8_t mouth; // 0 smile, 1 open, 2 flat, 3 wavy, 4 small "o"
  bool blush;
  bool rice_bowl;
  bool bowl_raised;
  bool sparkle;
  bool zzz;
  bool sweat;
  bool anger_mark;
  bool tail_high;
};

MascotPose mascot_pose(MascotMood mood, uint8_t frame);

enum class MascotReminder : uint8_t {
  None = 0,
  Hungry,
  BackupDue,
  LowBattery,
  PhoneNotLinked,
};

const char *mascot_reminder_text(MascotReminder reminder);

// Inputs the firmware already has; the companion only interprets them.
struct MascotInputs {
  bool backup_due;
  bool phone_linked;
  bool working;        // a signing or verification job is running
  uint16_t battery_mv; // 0 when the board has no fuel gauge
};

struct MascotStats {
  uint16_t approvals;
  uint16_t rejections;
  uint16_t pets;
  uint16_t feeds;
  uint16_t plays;
};

struct MascotSnapshot {
  MascotMood mood;
  MascotReminder reminder;
  MascotPose pose;
  uint8_t frame;
  uint8_t level;
  uint8_t hunger;   // 0 = full, 100 = starving
  uint8_t energy;   // 0 = exhausted, 100 = wide awake
  uint8_t bond;     // points inside the current level
  uint8_t bond_max; // points needed for the next level
  bool animating;   // true when the current mood has more than one frame
  MascotStats stats;
};

// Persisted fields: bounded, fixed size, no timestamps.
struct MascotPersisted {
  uint32_t magic;
  uint16_t approvals;
  uint16_t rejections;
  uint16_t pets;
  uint16_t feeds;
  uint16_t plays;
  uint16_t bond_points;
};

constexpr uint32_t kMascotPersistMagic = 0x4D415343UL;  // "MASC"
constexpr uint16_t kMascotPointsPerLevel = 25;
constexpr uint8_t kMascotMaxLevel = 9;
constexpr uint32_t kMascotSleepAfterMs = 5UL * 60UL * 1000UL;
constexpr uint32_t kMascotHungryAfterMs = 30UL * 60UL * 1000UL;
constexpr uint32_t kMascotStarvingAfterMs = 90UL * 60UL * 1000UL;
constexpr uint32_t kMascotReactionMs = 20UL * 1000UL;
constexpr uint32_t kMascotFrameMinMs = 30UL * 1000UL;
constexpr uint32_t kMascotAnimationMs = 700UL;
constexpr uint32_t kMascotActionCooldownMs = 2UL * 1000UL;

// Storage hooks supplied by the platform (NVS on device, a fake in tests).
struct MascotStore {
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

// Interactions. The bool results are false when the action was refused (cool
// down, too hungry to play), never because of an internal failure.
void mascot_note_approval(uint32_t now_ms);
void mascot_note_rejection(uint32_t now_ms);
bool mascot_pet(uint32_t now_ms);
bool mascot_feed(uint32_t now_ms);
bool mascot_play(uint32_t now_ms);
void mascot_note_activity(uint32_t now_ms);
void mascot_note_level_up(uint32_t now_ms);

MascotSnapshot mascot_snapshot(const MascotInputs &inputs, uint32_t now_ms);

// True at most once per kMascotFrameMinMs and only when the mood changed.
bool mascot_take_frame_request(uint32_t now_ms);

// True when the pose should advance, i.e. the next animation frame is due. The
// UI uses this to redraw only the pet, not the whole screen.
bool mascot_take_animation_tick(uint32_t now_ms);

void mascot_reset();

bool run_mascot_self_tests();

}

#endif
