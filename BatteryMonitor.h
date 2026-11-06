#ifndef HEXWALLET_BATTERY_MONITOR_H
#define HEXWALLET_BATTERY_MONITOR_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {
constexpr uint16_t kBatteryLowMillivolts = 3550;
constexpr uint16_t kBatteryCriticalMillivolts = 3350;
constexpr uint16_t kBatteryHysteresisMillivolts = 60;
constexpr size_t kBatterySampleHistory = 5;
constexpr uint32_t kBatterySampleIntervalMs = 5000;

enum class BatteryLevel : uint8_t {
  Unknown = 0,
  Nominal,
  Low,
  Critical,
};

struct BatteryFilter {
  uint16_t samples[kBatterySampleHistory];
  size_t count;
  size_t next;
  BatteryLevel level;

  void reset();
  void push(uint16_t millivolts);
  uint16_t median() const;
  BatteryLevel classify() const;
};

BatteryLevel battery_filter_add(BatteryFilter *filter, uint16_t millivolts);

struct BatteryStatus {
  uint16_t millivolts;
  BatteryLevel level;
};

void battery_monitor_init();
BatteryStatus battery_monitor_poll(uint32_t now_ms);
BatteryStatus battery_monitor_status();
bool battery_monitor_blocks_signing();
const char *battery_level_text(BatteryLevel level);

bool run_battery_monitor_self_test();

}

#endif
