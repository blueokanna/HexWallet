#include "Mascot.h"

namespace hexwallet {

namespace {

struct MascotRuntime {
  MascotStore store;
  bool store_bound;
  MascotPersisted data;
  uint32_t last_event_ms;
  uint32_t last_feed_ms;
  uint32_t last_reject_ms;
  uint32_t last_levelup_ms;
  uint32_t last_action_ms;
  uint32_t last_frame_ms;
  uint32_t last_anim_ms;
  MascotMood reaction;
  bool celebrated;  // excited already fired for this level
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

uint8_t level_of(uint16_t points) {
  uint32_t level = 1 + points / kMascotPointsPerLevel;
  if (level > kMascotMaxLevel) level = kMascotMaxLevel;
  return static_cast<uint8_t>(level);
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

bool within(uint32_t now_ms, uint32_t since_ms, uint32_t window_ms) {
  return static_cast<int32_t>(now_ms - since_ms) < static_cast<int32_t>(window_ms);
}

MascotMood derive_mood(const MascotInputs &inputs, uint8_t hunger, uint32_t now_ms) {
  // Order is policy. Needs come before reactions: a starving pet shows that even
  // if something nice just happened, and a running signing job outranks both
  // because the user must see that the device is busy.
  if (inputs.working) return MascotMood::Working;
  if (runtime.reaction == MascotMood::Eating &&
      within(now_ms, runtime.last_event_ms, kMascotReactionMs * 3)) {
    return MascotMood::Eating;
  }
  if (hunger >= 70) return MascotMood::Angry;
  if (static_cast<int32_t>(now_ms - runtime.last_event_ms) >=
      static_cast<int32_t>(kMascotSleepAfterMs)) {
    return MascotMood::Sleep;
  }
  if (runtime.reaction != MascotMood::Calm &&
      within(now_ms, runtime.last_event_ms, kMascotReactionMs)) {
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

bool mood_animates(MascotMood mood) {
  // Every mood has two frames, but a running or sleeping pet must not repaint
  // the panel for nothing.
  return mood != MascotMood::Working;
}

}  // namespace

const char *mascot_mood_name(MascotMood mood) {
  switch (mood) {
    case MascotMood::Calm: return "calm";
    case MascotMood::Happy: return "happy";
    case MascotMood::Alert: return "alert";
    case MascotMood::Angry: return "angry";
    case MascotMood::Eating: return "eating";
    case MascotMood::Excited: return "excited";
    case MascotMood::Working: return "working";
    case MascotMood::Sleep: return "sleep";
    case MascotMood::Shy: return "shy";
  }
  return "calm";
}

MascotPose mascot_pose(MascotMood mood, uint8_t frame) {
  // Eyes: 0 open, 1 closed, 2 happy arc, 3 angry.
  // Mouth: 0 smile, 1 open, 2 flat, 3 wavy, 4 small o.
  MascotPose pose = {};
  const bool second = (frame & 1U) != 0;
  switch (mood) {
    case MascotMood::Calm:
      pose.eyes = second ? 1 : 0;
      pose.mouth = 0;
      pose.blush = true;
      pose.tail_high = second;
      break;
    case MascotMood::Happy:
      pose.eyes = 2;
      pose.mouth = 1;
      pose.blush = true;
      pose.sparkle = true;
      pose.tail_high = second;
      break;
    case MascotMood::Alert:
      pose.eyes = 0;
      pose.mouth = 4;
      pose.sweat = true;
      pose.tail_high = true;
      break;
    case MascotMood::Angry:
      pose.eyes = 3;
      pose.mouth = 3;
      pose.anger_mark = true;
      pose.tail_high = second;
      break;
    case MascotMood::Eating:
      pose.eyes = 2;
      pose.mouth = 1;
      pose.blush = true;
      pose.rice_bowl = true;
      pose.bowl_raised = second;
      break;
    case MascotMood::Excited:
      pose.eyes = 2;
      pose.mouth = 1;
      pose.blush = true;
      pose.sparkle = true;
      pose.tail_high = true;
      break;
    case MascotMood::Working:
      pose.eyes = 0;
      pose.mouth = 2;
      pose.sweat = true;
      break;
    case MascotMood::Sleep:
      pose.eyes = 1;
      pose.mouth = 0;
      pose.zzz = true;
      pose.tail_high = second;
      break;
    case MascotMood::Shy:
      pose.eyes = 1;
      pose.mouth = 0;
      pose.blush = true;
      pose.sparkle = second;
      break;
  }
  return pose;
}

const char *mascot_reminder_text(MascotReminder reminder) {
  switch (reminder) {
    case MascotReminder::None: return "";
    case MascotReminder::Hungry: return "Rice time. Feed me first.";
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
  const uint8_t before = level_of(runtime.data.bond_points);
  ++runtime.data.approvals;
  bump_points(5);
  if (level_of(runtime.data.bond_points) > before) {
    mascot_note_level_up(now_ms);
  } else {
    set_reaction(MascotMood::Happy, now_ms);
  }
  mascot_save();
}

void mascot_note_rejection(uint32_t now_ms) {
  ++runtime.data.rejections;
  drop_points(2);
  const bool repeated = runtime.last_reject_ms != 0 &&
                        within(now_ms, runtime.last_reject_ms, 2UL * 60UL * 1000UL);
  runtime.last_reject_ms = now_ms;
  // One rejection is a warning; two in a row is a sulk. It is still only a
  // face - the reject itself is the wallet's decision, not hers.
  set_reaction(repeated ? MascotMood::Angry : MascotMood::Alert, now_ms);
  mascot_save();
}

void mascot_note_level_up(uint32_t now_ms) {
  runtime.last_levelup_ms = now_ms;
  set_reaction(MascotMood::Excited, now_ms);
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
  set_reaction(MascotMood::Eating, now_ms);
  mascot_save();
  return true;
}

bool mascot_play(uint32_t now_ms) {
  if (!cooldown_elapsed(now_ms)) return false;
  // Too hungry to play: she says so with a sulk instead of a happy frame.
  if (hunger_percent(now_ms) >= 80) {
    set_reaction(MascotMood::Angry, now_ms);
    return false;
  }
  runtime.last_action_ms = now_ms;
  ++runtime.data.plays;
  bump_points(3);
  set_reaction(MascotMood::Excited, now_ms);
  mascot_save();
  return true;
}

void mascot_note_activity(uint32_t now_ms) { runtime.last_event_ms = now_ms; }

MascotSnapshot mascot_snapshot(const MascotInputs &inputs, uint32_t now_ms) {
  MascotSnapshot snapshot = {};
  const uint8_t hunger = hunger_percent(now_ms);
  snapshot.mood = derive_mood(inputs, hunger, now_ms);
  snapshot.reminder = derive_reminder(inputs, hunger);
  snapshot.hunger = hunger;
  snapshot.energy = energy_percent(hunger, now_ms);
  snapshot.animating = mood_animates(snapshot.mood);
  snapshot.frame = snapshot.animating
                       ? static_cast<uint8_t>((now_ms / kMascotAnimationMs) & 1U)
                       : 0;
  snapshot.pose = mascot_pose(snapshot.mood, snapshot.frame);

  snapshot.level = level_of(runtime.data.bond_points);
  snapshot.bond = static_cast<uint8_t>(runtime.data.bond_points % kMascotPointsPerLevel);
  snapshot.bond_max = kMascotPointsPerLevel;
  if (snapshot.level >= kMascotMaxLevel) snapshot.bond = kMascotPointsPerLevel;

  snapshot.stats.approvals = runtime.data.approvals;
  snapshot.stats.rejections = runtime.data.rejections;
  snapshot.stats.pets = runtime.data.pets;
  snapshot.stats.feeds = runtime.data.feeds;
  snapshot.stats.plays = runtime.data.plays;
  return snapshot;
}

bool mascot_take_frame_request(uint32_t now_ms) {
  if (!runtime.frame_pending) return false;
  if (runtime.last_frame_ms != 0 &&
      static_cast<int32_t>(now_ms - runtime.last_frame_ms) <
          static_cast<int32_t>(kMascotFrameMinMs)) {
    return false;
  }
  runtime.last_frame_ms = now_ms;
  runtime.frame_pending = false;
  return true;
}

bool mascot_take_animation_tick(uint32_t now_ms) {
  if (runtime.frame_pending) return false;
  if (static_cast<int32_t>(now_ms - runtime.last_anim_ms) <
      static_cast<int32_t>(kMascotAnimationMs)) {
    return false;
  }
  runtime.last_anim_ms = now_ms;
  return true;
}

void mascot_reset() { reset_defaults(); }

namespace {

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

  MascotSnapshot snapshot = mascot_snapshot(inputs, 1000);
  passed = snapshot.mood == MascotMood::Calm && passed;
  passed = snapshot.level == 1 && passed;
  passed = snapshot.hunger == 0 && passed;
  // Calm blinks: the pose follows the animation frame, so assert the pairing
  // rather than a fixed value.
  passed = snapshot.pose.eyes == (snapshot.frame != 0 ? 1 : 0) && passed;
  passed = snapshot.pose.blush && passed;
  passed = snapshot.reminder == MascotReminder::None && passed;

  // Approval raises bond, shows Happy, and one point set does not skip a level.
  mascot_note_approval(2000);
  snapshot = mascot_snapshot(inputs, 2000);
  passed = snapshot.mood == MascotMood::Happy && passed;
  passed = snapshot.pose.eyes == 2 && passed;
  passed = snapshot.pose.sparkle && passed;
  passed = snapshot.bond == 5 && passed;
  passed = mascot_snapshot(inputs, 2000 + kMascotReactionMs + 1).mood == MascotMood::Calm && passed;

  // Five approvals cross the level boundary and celebrate exactly once.
  mascot_reset();
  for (int index = 0; index < 4; ++index) mascot_note_approval(1000 + index);
  passed = mascot_snapshot(inputs, 4000).mood == MascotMood::Happy && passed;
  mascot_note_approval(4001);
  snapshot = mascot_snapshot(inputs, 4001);
  passed = snapshot.level == 2 && passed;
  passed = snapshot.mood == MascotMood::Excited && passed;
  passed = snapshot.bond == 0 && passed;

  // Rejection: Alert first, Angry when it repeats inside the window.
  mascot_reset();
  mascot_note_rejection(1000);
  passed = mascot_snapshot(inputs, 1000).mood == MascotMood::Alert && passed;
  passed = mascot_snapshot(inputs, 1000).pose.sweat && passed;
  mascot_note_rejection(2000);
  snapshot = mascot_snapshot(inputs, 2000);
  passed = snapshot.mood == MascotMood::Angry && passed;
  passed = snapshot.pose.eyes == 3 && passed;
  passed = snapshot.pose.anger_mark && passed;
  passed = snapshot.bond == 0 && passed;

  // Feeding plays the eating animation, then hunger is gone.
  mascot_reset();
  passed = mascot_feed(1000) && passed;
  snapshot = mascot_snapshot(inputs, 1000);
  passed = snapshot.mood == MascotMood::Eating && passed;
  passed = snapshot.pose.rice_bowl && passed;
  passed = snapshot.hunger == 0 && passed;
  passed = mascot_pose(MascotMood::Eating, 1).bowl_raised && passed;
  passed = !mascot_pose(MascotMood::Eating, 0).bowl_raised && passed;

  // Working outranks everything, including a fresh reaction.
  mascot_reset();
  mascot_note_approval(1000);
  MascotInputs busy = inputs;
  busy.working = true;
  snapshot = mascot_snapshot(busy, 1100);
  passed = snapshot.mood == MascotMood::Working && passed;
  passed = !snapshot.animating && passed;

  // Starving: mood is Angry and play is refused.
  mascot_reset();
  snapshot = mascot_snapshot(inputs, kMascotStarvingAfterMs);
  passed = snapshot.mood == MascotMood::Angry && passed;
  passed = snapshot.reminder == MascotReminder::Hungry && passed;
  passed = !mascot_play(kMascotStarvingAfterMs) && passed;
  passed = mascot_snapshot(inputs, kMascotStarvingAfterMs).mood == MascotMood::Angry && passed;

  // Petting is Shy; playing when fed is Excited.
  mascot_reset();
  passed = mascot_pet(1000) && passed;
  passed = mascot_snapshot(inputs, 1000).mood == MascotMood::Shy && passed;
  mascot_reset();
  passed = mascot_play(1000) && passed;
  passed = mascot_snapshot(inputs, 1000).mood == MascotMood::Excited && passed;

  // Sleep is derived from idle time and cleared by activity.
  mascot_reset();
  passed = mascot_snapshot(inputs, kMascotSleepAfterMs + 1).mood == MascotMood::Sleep && passed;
  passed = mascot_snapshot(inputs, kMascotSleepAfterMs + 1).pose.zzz && passed;
  mascot_note_activity(kMascotSleepAfterMs + 2);
  passed = mascot_snapshot(inputs, kMascotSleepAfterMs + 2).mood == MascotMood::Calm && passed;

  // Every mood has a distinct pose table entry and a defined name.
  for (uint8_t mood = 0; mood < kMascotMoodCount; ++mood) {
    const MascotMood value = static_cast<MascotMood>(mood);
    passed = mascot_mood_name(value) != nullptr && passed;
    const MascotPose first = mascot_pose(value, 0);
    const MascotPose second = mascot_pose(value, 1);
    passed = first.eyes <= 3 && first.mouth <= 4 && passed;
    passed = second.eyes <= 3 && second.mouth <= 4 && passed;
  }

  // Cooldowns, bond floor, persistence and the animation tick.
  mascot_reset();
  passed = mascot_feed(1000) && passed;
  passed = !mascot_feed(1000 + kMascotActionCooldownMs - 1) && passed;
  passed = mascot_feed(1000 + kMascotActionCooldownMs) && passed;

  mascot_reset();
  FakeStore fake = {};
  const MascotStore store = {&fake, fake_load, fake_save};
  passed = !mascot_save() && passed;
  mascot_bind_store(store);
  mascot_note_approval(1000);
  passed = mascot_save() && passed;
  passed = fake.value.magic == kMascotPersistMagic && passed;
  passed = fake.value.approvals == 1 && passed;
  mascot_reset();
  passed = mascot_load() && passed;
  passed = mascot_snapshot(inputs, 2000).stats.approvals == 1 && passed;
  fake.value.magic = 0xDEADBEEFUL;
  mascot_reset();
  passed = !mascot_load() && passed;

  mascot_reset();
  passed = mascot_take_frame_request(0) && passed;
  passed = !mascot_take_frame_request(1000) && passed;
  passed = !mascot_take_animation_tick(0) && passed;
  passed = !mascot_take_animation_tick(kMascotAnimationMs - 1) && passed;
  passed = mascot_take_animation_tick(kMascotAnimationMs) && passed;

  const MascotStore unbound = {};
  mascot_bind_store(unbound);
  mascot_reset();
  return passed;
}

}  // namespace hexwallet
