#ifndef HEXWALLET_CAMERA_PORT_H
#define HEXWALLET_CAMERA_PORT_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// OV9281 presence layer.
//
// The sensor is a MIPI CSI-2 part: 1280x800 global-shutter mono, 8/10-bit RAW,
// programmed over SCCB (OmniVision's I2C variant) and streamed over the CSI
// lanes. This file covers the part that can be specified without the module
// vendor's register table: address the sensor, read its chip ID, and classify
// the outcome. It deliberately does not pretend to stream frames - a made-up
// init table produces a camera that returns noise, and a wallet that shows a
// noisy frame as a scanned address is worse than one that says "no camera".
//
// Board reality check (rev c26102103, from the EasyEDA project): the ESP32-P4
// CSI pins carry series resistors R31-R37 and the camera FPC footprint has no
// nets, so no SCCB bus reaches an OV9281 on this revision. camera_probe()
// returns NotConfigured there instead of inventing pins.

enum class CameraProbeState : uint8_t {
  NotConfigured = 0,  // the board profile wires no SCCB bus
  NoResponse,         // the sensor did not acknowledge its SCCB address
  WrongSensor,        // something answered, but the chip ID is not an OV9281
  PresentUnverified,  // the OV9281 chip ID was read back correctly
};

struct CameraInfo {
  uint16_t chip_id;      // 0x9281 for an OV9281
  uint8_t sccb_address;  // 8-bit SCCB address the probe used
};

// SCCB transport supplied by the board port. `address` is the 8-bit SCCB write
// address; reads are a register write followed by a repeated start, which is
// what the `read` callback is expected to do.
struct CameraSccbBus {
  void *context;
  bool (*write)(void *context, uint8_t address, uint16_t reg, uint8_t value);
  bool (*read)(void *context, uint8_t address, uint16_t reg, uint8_t *value);
  void (*delay_ms)(void *context, uint32_t milliseconds);
};

constexpr uint8_t kOv9281SccbAddress = 0x60;  // 0x30 << 1
constexpr uint16_t kOv9281ChipIdHighRegister = 0x300A;
constexpr uint16_t kOv9281ChipIdLowRegister = 0x300B;
constexpr uint16_t kOv9281ChipId = 0x9281;

// Reads the chip ID and classifies the result. A NAK on either half is
// NoResponse; a mismatched ID is WrongSensor. Only a full, matching read is
// PresentUnverified, which still says nothing about the CSI link or the
// register table.
CameraProbeState camera_probe(const CameraSccbBus &bus, CameraInfo *info);

// Convenience wrapper for callers that only need the verdict.
bool camera_present(const CameraSccbBus &bus);

bool run_camera_port_self_tests();

}

#endif
