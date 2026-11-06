#include "BatteryMonitor.h"

#include <string.h>

#if defined(ARDUINO)
#include "WalletBoardPort.h"
#endif

namespace hexwallet
{
  namespace
  {

    BatteryFilter g_filter;
    uint32_t g_last_sample_ms = 0;
    bool g_sampled = false;

  }

  void BatteryFilter::reset()
  {
    memset(samples, 0, sizeof(samples));
    count = 0;
    next = 0;
    level = BatteryLevel::Unknown;
  }

  void BatteryFilter::push(uint16_t millivolts)
  {
    samples[next] = millivolts;
    next = (next + 1) % kBatterySampleHistory;
    if (count < kBatterySampleHistory)
    {
      ++count;
    }
    level = classify();
  }

  uint16_t BatteryFilter::median() const
  {
    if (count == 0)
    {
      return 0;
    }
    uint16_t sorted[kBatterySampleHistory];
    for (size_t index = 0; index < count; ++index)
    {
      uint16_t value = samples[index];
      size_t slot = index;
      while (slot > 0 && sorted[slot - 1] > value)
      {
        sorted[slot] = sorted[slot - 1];
        --slot;
      }
      sorted[slot] = value;
    }
    return sorted[count / 2];
  }

  BatteryLevel BatteryFilter::classify() const
  {
    if (count == 0)
    {
      return BatteryLevel::Unknown;
    }
    const uint16_t millivolts = median();
    const bool at_critical = millivolts <= kBatteryCriticalMillivolts;
    const bool at_low = millivolts <= kBatteryLowMillivolts;
    const bool recovered_low =
        millivolts > static_cast<uint16_t>(kBatteryCriticalMillivolts + kBatteryHysteresisMillivolts);
    const bool recovered_nominal =
        millivolts > static_cast<uint16_t>(kBatteryLowMillivolts + kBatteryHysteresisMillivolts);
    switch (level)
    {
    case BatteryLevel::Critical:
      return recovered_low ? (recovered_nominal ? BatteryLevel::Nominal : BatteryLevel::Low)
                           : BatteryLevel::Critical;
    case BatteryLevel::Low:
      return at_critical ? BatteryLevel::Critical
                         : (recovered_nominal ? BatteryLevel::Nominal : BatteryLevel::Low);
    case BatteryLevel::Nominal:
    case BatteryLevel::Unknown:
      return at_critical ? BatteryLevel::Critical : (at_low ? BatteryLevel::Low : BatteryLevel::Nominal);
    }
    return BatteryLevel::Unknown;
  }

  BatteryLevel battery_filter_add(BatteryFilter *filter, uint16_t millivolts)
  {
    if (filter == nullptr)
    {
      return BatteryLevel::Unknown;
    }
    filter->push(millivolts);
    return filter->level;
  }

  void battery_monitor_init()
  {
    g_filter.reset();
    g_last_sample_ms = 0;
    g_sampled = false;
  }

  BatteryStatus battery_monitor_status()
  {
    BatteryStatus status;
    status.millivolts = g_filter.median();
    status.level = g_filter.level;
    return status;
  }

  bool battery_monitor_blocks_signing()
  {
    return g_filter.level == BatteryLevel::Critical;
  }

  BatteryStatus battery_monitor_poll(uint32_t now_ms)
  {
#if defined(ARDUINO)
    const bool due = !g_sampled || static_cast<uint32_t>(now_ms - g_last_sample_ms) >= kBatterySampleIntervalMs;
    if (due)
    {
      g_last_sample_ms = now_ms;
      g_sampled = true;
      const uint16_t millivolts = board_battery_millivolts();
      if (millivolts != 0)
      {
        battery_filter_add(&g_filter, millivolts);
      }
    }
#else
    (void)now_ms;
#endif
    return battery_monitor_status();
  }

  const char *battery_level_text(BatteryLevel level)
  {
    switch (level)
    {
    case BatteryLevel::Unknown:
      return "unknown";
    case BatteryLevel::Nominal:
      return "nominal";
    case BatteryLevel::Low:
      return "low";
    case BatteryLevel::Critical:
      return "critical";
    }
    return "unknown";
  }

  bool run_battery_monitor_self_test()
  {
    bool passed = true;

    BatteryFilter filter;
    filter.reset();
    passed = passed && filter.count == 0 && filter.level == BatteryLevel::Unknown;
    passed = passed && filter.median() == 0;
    passed = passed && battery_filter_add(nullptr, 4000) == BatteryLevel::Unknown;

    for (int sample = 0; sample < 3; ++sample)
    {
      passed = passed && battery_filter_add(&filter, 4000) == BatteryLevel::Nominal;
    }

    passed = passed && battery_filter_add(&filter, 3300) == BatteryLevel::Nominal;
    passed = passed && filter.median() == 4000;

    for (int sample = 0; sample < kBatterySampleHistory; ++sample)
    {
      battery_filter_add(&filter, 3300);
    }
    passed = passed && filter.level == BatteryLevel::Critical;
    passed = passed && filter.median() == 3300;

    for (int sample = 0; sample < kBatterySampleHistory; ++sample)
    {
      battery_filter_add(&filter, 3420);
    }
    passed = passed && filter.level == BatteryLevel::Low;

    for (int sample = 0; sample < kBatterySampleHistory; ++sample)
    {
      battery_filter_add(&filter, 3560);
    }
    passed = passed && filter.level == BatteryLevel::Low;

    for (int sample = 0; sample < kBatterySampleHistory; ++sample)
    {
      battery_filter_add(&filter, 3700);
    }
    passed = passed && filter.level == BatteryLevel::Nominal;
    passed = passed && filter.median() == 3700;

    BatteryFilter fresh;
    fresh.reset();
    for (int sample = 0; sample < kBatterySampleHistory; ++sample)
    {
      battery_filter_add(&fresh, 4000);
    }
    for (int sample = 0; sample < kBatterySampleHistory; ++sample)
    {
      battery_filter_add(&fresh, 3560);
    }
    passed = passed && fresh.level == BatteryLevel::Nominal;

    passed = passed && strcmp(battery_level_text(BatteryLevel::Critical), "critical") == 0;
    passed = passed && strcmp(battery_level_text(BatteryLevel::Unknown), "unknown") == 0;

    battery_monitor_init();
    const BatteryStatus status = battery_monitor_poll(1000);
    passed = passed && status.level == BatteryLevel::Unknown && status.millivolts == 0 &&
             !battery_monitor_blocks_signing();
    return passed;
  }

}
