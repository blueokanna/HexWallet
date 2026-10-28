#ifndef HEXWALLET_SE051_ARDUINO_PORT_H
#define HEXWALLET_SE051_ARDUINO_PORT_H

// Use instead of NXP Linux i2c_a7.c and generic sm_timer.c. Transport support
// alone does not enable hardware custody or provision SCP03 keys.
#ifndef HEXWALLET_ENABLE_NXP_SE051
#define HEXWALLET_ENABLE_NXP_SE051 0
#endif
namespace hexwallet {
// Diagnostics must not reset or read Wire1 while the SDK owns it.
bool se051_transport_in_use();
}
#endif
