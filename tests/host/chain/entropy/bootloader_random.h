#pragma once

void bootloader_random_enable();
void bootloader_random_disable();

namespace boot_entropy_test {
extern bool adc_enabled;
extern unsigned starts, reads, fail_on;
}
