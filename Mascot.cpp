#include "Mascot.h"

namespace hexwallet {

namespace {

struct MascotRuntime {
  MascotStore store;
  bool store_bound;
  MascotPersisted data;
  uint32_t last_event_ms;
  uint32_t last_feed_ms;
  uint32_t last_action_ms;
  uint32_t last_frame_ms;
  bool drew_frame;
  MascotMood reaction;
  bool frame_pending;
};

MascotRuntime runtime = {};

void reset_defaults() {
  const MascotStore previous_store = runtime.store;
  const bool previous_bound = runtime.store_bound;
  runtime = {};
  runtime.store = previous_store;
  runtime.store_bound = previous_bound;
  runtime.data.magic = kMascotPersistMagic;
  runtime.reaction = MascotMood::Calm;
  runtime.frame_pending = true;
}

void bump_points(uint16_t points) {
  const uint32_t total = static_cast<uint32_t>(runtime.data.bond_points) + points;
  runtime.data.bond_points = total > 0xFFFFU ? 0xFFFFU : static_cast<uint16_t>(total);
}

void drop_points(uint16_t points) {
  runtime.data.bond_points =
      runtime.data.bond_points > points
          ? static_cast<uint16_t>(runtime.data.bond_points - points)
          : 0;
}

void set_reaction(MascotMood mood, uint32_t now_ms) {
  if (runtime.reaction != mood) {
    runtime.reaction = mood;
    runtime.frame_pending = true;
  }
  runtime.last_event_ms = now_ms;
}

bool cooldown_elapsed(uint32_t now_ms) {
  if (runtime.last_action_ms == 0) return true;
  return static_cast<int32_t>(now_ms - runtime.last_action_ms) >=
         static_cast<int32_t>(kMascotActionCooldownMs);
}

uint8_t hunger_percent(uint32_t now_ms) {
  const uint32_t elapsed = now_ms - runtime.last_feed_ms;
  if (elapsed >= kMascotStarvingAfterMs) return 100;
  return static_cast<uint8_t>((elapsed * 100UL) / kMascotStarvingAfterMs);
}

uint8_t energy_percent(uint8_t hunger, uint32_t now_ms) {
  const uint32_t idle = now_ms - runtime.last_event_ms;
  uint32_t energy = 100;
  if (idle >= kMascotSleepAfterMs) {
    energy = 45;
  } else {
    energy = 100 - (idle * 55UL) / kMascotSleepAfterMs;
  }
  if (hunger > 60) energy = energy > 20 ? energy - 20 : 0;
  return static_cast<uint8_t>(energy > 100 ? 100 : energy);
}

MascotMood derive_mood(uint8_t hunger, uint32_t now_ms) {
  // Priority is a policy, not a preference: a starving companion shows that
  // even if it just watched an approval.
  if (hunger >= 70) return MascotMood::Hungry;
  if (static_cast<int32_t>(now_ms - runtime.last_event_ms) >=
      static_cast<int32_t>(kMascotSleepAfterMs)) {
    return MascotMood::Sleep;
  }
  if (runtime.reaction != MascotMood::Calm &&
      static_cast<int32_t>(now_ms - runtime.last_event_ms) <
          static_cast<int32_t>(kMascotReactionMs)) {
    return runtime.reaction;
  }
  return MascotMood::Calm;
}

MascotReminder derive_reminder(const MascotInputs &inputs, uint8_t hunger) {
  if (inputs.backup_due) return MascotReminder::BackupDue;
  if (inputs.battery_mv != 0 && inputs.battery_mv < 3300) {
    return MascotReminder::LowBattery;
  }
  if (hunger >= 70) return MascotReminder::Hungry;
  if (!inputs.phone_linked) return MascotReminder::PhoneNotLinked;
  return MascotReminder::None;
}

}  // namespace

const char *mascot_mood_name(MascotMood mood) {
  switch (mood) {
    case MascotMood::Calm: return "calm";
    case MascotMood::Happy: return "happy";
    case MascotMood::Alert: return "alert";
    case MascotMood::Sleep: return "sleep";
    case MascotMood::Hungry: return "hungry";
    case MascotMood::Shy: return "shy";
  }
  return "calm";
}

const char *mascot_reminder_text(MascotReminder reminder) {
  switch (reminder) {
    case MascotReminder::None: return "";
    case MascotReminder::Hungry: return "I could eat a bowl of rice.";
    case MascotReminder::BackupDue: return "Back up the seed phrase first.";
    case MascotReminder::LowBattery: return "Battery low - charge before signing.";
    case MascotReminder::PhoneNotLinked: return "No paired phone yet.";
  }
  return "";
}

void mascot_bind_store(const MascotStore &store) {
  runtime.store = store;
  runtime.store_bound = store.load != nullptr && store.save != nullptr;
}

bool mascot_save() {
  if (!runtime.store_bound) return false;
  runtime.data.magic = kMascotPersistMagic;
  return runtime.store.save(runtime.store.context, runtime.data);
}
bool mascot_load() {
  if (!runtime.store_bound) return false;
  MascotPersisted loaded = {};
  if (!runtime.store.load(runtime.store.context, &loaded)) return false;
  if (loaded.magic != kMascotPersistMagic) return false;
  runtime.data = loaded;
  runtime.frame_pending = true;
  return true;
}

void mascot_note_approval(uint32_t now_ms) {
  ++runtime.data.approvals;
  bump_points(5);
  set_reaction(MascotMood::Happy, now_ms);
  mascot_save();
}

void mascot_note_rejection(uint32_t now_ms) {
  ++runtime.data.rejections;
  drop_points(2);
  set_reaction(MascotMood::Alert, now_ms);
  mascot_save();
}

bool mascot_pet(uint32_t now_ms) {
  if (!cooldown_elapsed(now_ms)) return false;
  runtime.last_action_ms = now_ms;
  ++runtime.data.pets;
  bump_points(1);
  set_reaction(MascotMood::Shy, now_ms);
  mascot_save();
  return true;
}

bool mascot_feed(uint32_t now_ms) {
  if (!cooldown_elapsed(now_ms)) return false;
  runtime.last_action_ms = now_ms;
  runtime.last_feed_ms = now_ms;
  ++runtime.data.feeds;
  bump_points(2);
  set_reaction(MascotMood::Happy, now_ms);
  mascot_save();
  return true;
}

bool mascot_play(uint32_t now_ms) {
  if (!cooldown_elapsed(now_ms)) return false;
  // A starving companion refuses to play. Saying so is better than animating a
  // happy frame while the hunger bar is red.
  if (hunger_percent(now_ms) >= 80) return false;
  runtime.last_action_ms = now_ms;
  ++runtime.data.plays;
  bump_points(3);
  set_reaction(MascotMood::Happy, now_ms);
  mascot_save();
  return true;
}

void mascot_note_activity(uint32_t now_ms) { runtime.last_event_ms = now_ms; }

MascotSnapshot mascot_snapshot(const MascotInputs &inputs, uint32_t now_ms) {
  MascotSnapshot snapshot = {};
  const uint8_t hunger = hunger_percent(now_ms);
  snapshot.mood = derive_mood(hunger, now_ms);
  snapshot.reminder = derive_reminder(inputs, hunger);
  snapshot.hunger = hunger;
  snapshot.energy = energy_percent(hunger, now_ms);

  uint32_t level = 1 + runtime.data.bond_points / kMascotPointsPerLevel;
  if (level > kMascotMaxLevel) level = kMascotMaxLevel;
  snapshot.level = static_cast<uint8_t>(level);
  snapshot.bond = static_cast<uint8_t>(runtime.data.bond_points % kMascotPointsPerLevel);
  snapshot.bond_max = kMascotPointsPerLevel;
  if (level >= kMascotMaxLevel) snapshot.bond = kMascotPointsPerLevel;

  snapshot.stats.approvals = runtime.data.approvals;
  snapshot.stats.rejections = runtime.data.rejections;
  snapshot.stats.pets = runtime.data.pets;
  snapshot.stats.feeds = runtime.data.feeds;
  snapshot.stats.plays = runtime.data.plays;
  return snapshot;
}

bool mascot_take_frame_request(uint32_t now_ms) {
  if (!runtime.frame_pending) return false;
  // The "have I drawn anything yet" flag, not a 0 timestamp: now_ms can be 0.
  if (runtime.drew_frame &&
      static_cast<int32_t>(now_ms - runtime.last_frame_ms) <
          static_cast<int32_t>(kMascotFrameMinMs)) {
    return false;
  }
  runtime.last_frame_ms = now_ms;
  runtime.drew_frame = true;
  runtime.frame_pending = false;
  return true;
}

uint8_t mascot_frame_index(uint32_t now_ms) {
  // Only the idle mood blinks; every other mood is a single frame that already
  // says what happened.
  if (derive_mood(hunger_percent(now_ms), now_ms) != MascotMood::Calm) return 0;
  return static_cast<uint8_t>((now_ms / 4000UL) & 1U);
}

void mascot_reset() { reset_defaults(); }

namespace {

// Fake NVS used by the self-test.
struct FakeStore {
  MascotPersisted value;
  bool valid;
  int saves;
  bool fail;
};

bool fake_load(void *context, MascotPersisted *out) {
  FakeStore *store = static_cast<FakeStore *>(context);
  if (store == nullptr || out == nullptr || !store->valid) return false;
  *out = store->value;
  return true;
}

bool fake_save(void *context, const MascotPersisted &value) {
  FakeStore *store = static_cast<FakeStore *>(context);
  if (store == nullptr || store->fail) return false;
  store->value = value;
  store->valid = true;
  ++store->saves;
  return true;
}

}  // namespace

bool run_mascot_self_tests() {
  bool passed = true;
  mascot_reset();

  MascotInputs inputs = {};
  inputs.phone_linked = true;

  // Fresh companion: calm, fed, level 1.
  MascotSnapshot snapshot = mascot_snapshot(inputs, 1000);
  passed = snapshot.mood == MascotMood::Calm && passed;
  passed = snapshot.level == 1 && passed;
  passed = snapshot.hunger == 0 && passed;
  passed = snapshot.stats.approvals == 0 && passed;
  passed = snapshot.reminder == MascotReminder::None && passed;

  // Approval raises bond and shows Happy for the reaction window.
  mascot_note_approval(2000);
  snapshot = mascot_snapshot(inputs, 2000);
  passed = snapshot.mood == MascotMood::Happy && passed;
  passed = snapshot.stats.approvals == 1 && passed;
  passed = snapshot.bond == 5 && passed;
  snapshot = mascot_snapshot(inputs, 2000 + kMascotReactionMs + 1);
  passed = snapshot.mood == MascotMood::Calm && passed;

  // Rejection lowers bond but never underflows.
  mascot_reset();
  mascot_note_rejection(1000);
  snapshot = mascot_snapshot(inputs, 1000);
  passed = snapshot.mood == MascotMood::Alert && passed;
  passed = snapshot.bond == 0 && passed;
  passed = snapshot.stats.rejections == 1 && passed;

  // Level maths: 25 points per level, capped at the maximum.
  mascot_reset();
  for (int index = 0; index < 5; ++index) mascot_note_approval(1000 + index);
  snapshot = mascot_snapshot(inputs, 2000);
  passed = snapshot.level == 2 && passed;
  passed = snapshot.bond == 0 && passed;
  passed = snapshot.bond_max == kMascotPointsPerLevel && passed;
  for (int index = 0; index < 200; ++index) mascot_note_approval(3000 + index);
  snapshot = mascot_snapshot(inputs, 4000);
  passed = snapshot.level == kMascotMaxLevel && passed;
  passed = snapshot.bond == kMascotPointsPerLevel && passed;

  // Hunger grows with time, saturates, and outranks every other mood.
  mascot_reset();
  passed = mascot_snapshot(inputs, 0).hunger == 0 && passed;
  passed = mascot_snapshot(inputs, kMascotStarvingAfterMs / 2).hunger == 50 && passed;
  passed = mascot_snapshot(inputs, kMascotStarvingAfterMs * 3).hunger == 100 && passed;
  mascot_note_approval(kMascotStarvingAfterMs * 3);
  passed = mascot_snapshot(inputs, kMascotStarvingAfterMs * 3).mood == MascotMood::Hungry && passed;
  passed = mascot_snapshot(inputs, kMascotStarvingAfterMs * 3).reminder ==
                   MascotReminder::Hungry && passed;

  // Feeding resets hunger and is cooldown limited.
  mascot_reset();
  passed = mascot_feed(1000) && passed;
  passed = mascot_snapshot(inputs, 1000).hunger == 0 && passed;
  passed = !mascot_feed(1000 + kMascotActionCooldownMs - 1) && passed;
  passed = mascot_feed(1000 + kMascotActionCooldownMs) && passed;

  // A starving companion refuses to play instead of pretending.
  mascot_reset();
  passed = !mascot_play(kMascotStarvingAfterMs) && passed;
  passed = mascot_play(0) && passed;

  // Petting is Shy.
  mascot_reset();
  passed = mascot_pet(1000) && passed;
  passed = mascot_snapshot(inputs, 1000).mood == MascotMood::Shy && passed;
  passed = mascot_snapshot(inputs, 1000).stats.pets == 1 && passed;

  // Sleep is derived from idle time and cleared by activity.
  mascot_reset();
  passed = mascot_snapshot(inputs, kMascotSleepAfterMs + 1).mood == MascotMood::Sleep && passed;
  mascot_note_activity(kMascotSleepAfterMs + 2);
  passed = mascot_snapshot(inputs, kMascotSleepAfterMs + 2).mood == MascotMood::Calm && passed;

  // Reminder priority: backup > battery > hunger > pairing.
  mascot_reset();
  MascotInputs all = {};
  all.backup_due = true;
  all.battery_mv = 3000;
  passed = mascot_snapshot(all, kMascotStarvingAfterMs * 2).reminder ==
                   MascotReminder::BackupDue && passed;
  all.backup_due = false;
  passed = mascot_snapshot(all, kMascotStarvingAfterMs * 2).reminder ==
                   MascotReminder::LowBattery && passed;
  all.battery_mv = 4000;
  passed = mascot_snapshot(all, kMascotStarvingAfterMs * 2).reminder ==
                   MascotReminder::Hungry && passed;
  passed = mascot_snapshot(all, 1000).reminder == MascotReminder::PhoneNotLinked && passed;

  // Persistence: counters survive a load, a bad magic is rejected, and an
  // unbound store reports failure instead of pretending to save.
  mascot_reset();
  FakeStore fake = {};
  const MascotStore store = {&fake, fake_load, fake_save};
  passed = !mascot_save() && passed;  // nothing bound yet
  mascot_bind_store(store);
  mascot_note_approval(1000);
  passed = mascot_pet(1000 + kMascotActionCooldownMs) && passed;
  passed = mascot_save() && passed;
  passed = fake.saves > 0 && passed;
  passed = fake.value.magic == kMascotPersistMagic && passed;
  passed = fake.value.approvals == 1 && passed;
  passed = fake.value.pets == 1 && passed;

  mascot_reset();
  passed = mascot_load() && passed;
  snapshot = mascot_snapshot(inputs, 2000);
  passed = snapshot.stats.approvals == 1 && passed;
  passed = snapshot.stats.pets == 1 && passed;

  fake.value.magic = 0xDEADBEEFUL;
  mascot_reset();
  passed = !mascot_load() && passed;
  fake.valid = false;
  passed = !mascot_load() && passed;

  // Frame requests are rate limited, and the first one after boot is not.
  mascot_reset();
  passed = mascot_take_frame_request(0) && passed;
  mascot_note_approval(kMascotFrameMinMs / 2);
  passed = !mascot_take_frame_request(kMascotFrameMinMs / 2) && passed;
  passed = mascot_take_frame_request(kMascotFrameMinMs + 2) && passed;

  // The idle blink alternates only while calm.
  mascot_reset();
  passed = mascot_frame_index(0) == 0 && passed;
  passed = mascot_frame_index(4000) == 1 && passed;
  mascot_note_approval(5000);
  passed = mascot_frame_index(5000) == 0 && passed;

  const MascotStore unbound = {};
  mascot_bind_store(unbound);
  mascot_reset();
  return passed;
}

}  // namespace hexwallet
