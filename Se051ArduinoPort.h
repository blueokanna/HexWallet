#ifndef HEXWALLET_SE051_ARDUINO_PORT_H
#define HEXWALLET_SE051_ARDUINO_PORT_H

#ifndef HEXWALLET_ENABLE_NXP_SE051
#define HEXWALLET_ENABLE_NXP_SE051 0
#endif
namespace hexwallet {
bool se051_transport_in_use();
}
#endif
