#ifndef HEXWALLET_CAMERA_PORT_H
#define HEXWALLET_CAMERA_PORT_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet {

// OV9281 presence layer.
//
// The sensor is a MIPI CSI-2 part: 1280x800 global-shutter mono, 8/10-bit RAW,
// programmed over SCCB (OmniVision's I2C variant) and streamed over the CSI
// lanes. This layer identifies the sensor. CameraBackup.cpp uses the pinned
// Espressif sensor driver and its mode table to acquire a grayscale frame.
//
// The c26102103 camera connector shares SCCB with the secure element and RTC.
// Board 7 probes the shared control bus before accessing the sensor.

enum class CameraProbeState : uint8_t {
  NotConfigured = 0, // the board profile wires no SCCB bus
  NoResponse,        // the sensor did not acknowledge its SCCB address
  WrongSensor,       // something answered, but the chip ID is not an OV9281
  PresentUnverified, // the OV9281 chip ID was read back correctly
};

struct CameraInfo {
  uint16_t chip_id;     // 0x9281 for an OV9281
  uint8_t sccb_address; // 7-bit I2C address of the responding sensor
};

// SCCB transport supplied by the board port. `address` is the 7-bit I2C
// address; reads are a register write followed by a repeated start, which is
// what the `read` callback is expected to do.
struct CameraSccbBus {
  void *context;
  bool (*write)(void *context, uint8_t address, uint16_t reg, uint8_t value);
  bool (*read)(void *context, uint8_t address, uint16_t reg, uint8_t *value);
  void (*delay_ms)(void *context, uint32_t milliseconds);
};

constexpr uint8_t kOv9281SccbAddress = 0x60; // SID low (0xc0 on the wire)
// OV9281 SID high and the factory programmable alias, in Wire notation.
constexpr uint8_t kOv9281Addresses[] = {kOv9281SccbAddress, 0x10, 0x70};
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

} // namespace hexwallet

#endif
