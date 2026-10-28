#include "CameraPort.h"

namespace hexwallet {

namespace {

bool bus_complete(const CameraSccbBus &bus) {
  return bus.write != nullptr && bus.read != nullptr;
}

}  // namespace

CameraProbeState camera_probe(const CameraSccbBus &bus, CameraInfo *info) {
  if (info != nullptr) {
    info->chip_id = 0;
    info->sccb_address = kOv9281SccbAddress;
  }
  if (!bus_complete(bus)) return CameraProbeState::NotConfigured;

  // The OV9281 needs its clock running before SCCB answers; boards that gate the
  // sensor clock need a settle delay here, so give it one unconditionally.
  if (bus.delay_ms != nullptr) bus.delay_ms(bus.context, 5);

  uint8_t high = 0;
  uint8_t low = 0;
  if (!bus.read(bus.context, kOv9281SccbAddress, kOv9281ChipIdHighRegister, &high)) {
    return CameraProbeState::NoResponse;
  }
  if (!bus.read(bus.context, kOv9281SccbAddress, kOv9281ChipIdLowRegister, &low)) {
    return CameraProbeState::NoResponse;
  }
  const uint16_t chip_id = static_cast<uint16_t>((high << 8) | low);
  if (info != nullptr) info->chip_id = chip_id;
  if (chip_id != kOv9281ChipId) return CameraProbeState::WrongSensor;
  return CameraProbeState::PresentUnverified;
}

bool camera_present(const CameraSccbBus &bus) {
  return camera_probe(bus, nullptr) == CameraProbeState::PresentUnverified;
}

namespace {

// Fake SCCB device used by the self-test. It models the two properties that
// matter: register addressing is 16-bit big-endian, and a missing device NAKs
// instead of returning zeros.
struct FakeSensor {
  uint16_t chip_id;
  bool ack;
  uint8_t written_high_register;
  uint8_t written_low_register;
  int writes;
};

bool fake_write(void *context, uint8_t address, uint16_t reg, uint8_t value) {
  FakeSensor *sensor = static_cast<FakeSensor *>(context);
  (void)value;
  if (sensor == nullptr || !sensor->ack) return false;
  if (address != kOv9281SccbAddress) return false;
  sensor->written_high_register = static_cast<uint8_t>(reg >> 8);
  sensor->written_low_register = static_cast<uint8_t>(reg & 0xFF);
  ++sensor->writes;
  return true;
}

bool fake_read(void *context, uint8_t address, uint16_t reg, uint8_t *value) {
  FakeSensor *sensor = static_cast<FakeSensor *>(context);
  if (sensor == nullptr || value == nullptr || !sensor->ack) return false;
  if (address != kOv9281SccbAddress) return false;
  if (reg == kOv9281ChipIdHighRegister) {
    *value = static_cast<uint8_t>(sensor->chip_id >> 8);
  } else if (reg == kOv9281ChipIdLowRegister) {
    *value = static_cast<uint8_t>(sensor->chip_id & 0xFF);
  } else {
    return false;
  }
  sensor->written_high_register = static_cast<uint8_t>(reg >> 8);
  sensor->written_low_register = static_cast<uint8_t>(reg & 0xFF);
  return true;
}

void fake_delay(void *context, uint32_t milliseconds) {
  (void)context;
  (void)milliseconds;
}

}  // namespace

bool run_camera_port_self_tests() {
  bool passed = true;

  // No transport at all must never look like a present sensor.
  const CameraSccbBus empty = {};
  passed = camera_probe(empty, nullptr) == CameraProbeState::NotConfigured && passed;
  passed = !camera_present(empty) && passed;

  FakeSensor sensor = {};
  sensor.chip_id = kOv9281ChipId;
  sensor.ack = true;
  const CameraSccbBus bus = {&sensor, fake_write, fake_read, fake_delay};
  CameraInfo info = {};
  passed = camera_probe(bus, &info) == CameraProbeState::PresentUnverified && passed;
  passed = info.chip_id == kOv9281ChipId && passed;
  passed = info.sccb_address == kOv9281SccbAddress && passed;
  passed = camera_present(bus) && passed;

  // A sensor that does not acknowledge is NoResponse, not "absent hardware".
  sensor.ack = false;
  const CameraInfo silent = {};
  passed = camera_probe(bus, nullptr) == CameraProbeState::NoResponse && passed;
  (void)silent;

  // A different OmniVision part on the same bus must be reported as such: this
  // is the check that stops a "supported" camera from being the wrong sensor.
  sensor.ack = true;
  sensor.chip_id = 0x5640;  // OV5640
  info = {};
  passed = camera_probe(bus, &info) == CameraProbeState::WrongSensor && passed;
  passed = info.chip_id == 0x5640 && passed;

  // A bus missing one callback is not usable.
  const CameraSccbBus half = {&sensor, fake_write, nullptr, fake_delay};
  passed = camera_probe(half, nullptr) == CameraProbeState::NotConfigured && passed;

  // A null info pointer must not crash the probe.
  sensor.chip_id = kOv9281ChipId;
  passed = camera_probe(bus, nullptr) == CameraProbeState::PresentUnverified && passed;
  return passed;
}

}  // namespace hexwallet
