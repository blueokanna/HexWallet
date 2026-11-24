// Board 7 bring-up using internal SRAM, the P4 ROM and USB Serial/JTAG.
// No flash, filesystem, credential APDUs, RF discovery or card emulation.
#include "WalletBoardPins.h"
#include "CameraPort.h"
#include "esp32p4/rom/gpio.h"
#include "hal/gpio_ll.h"
#include "hal/rtc_io_ll.h"
#include "hal/usb_serial_jtag_ll.h"
#include "soc/gpio_sig_map.h"

extern "C" void ets_delay_us(uint32_t us);
asm(".section .text.start,\"ax\"\n.global probe_start\nprobe_start:\n"
    "la sp, _stack_top\ncsrci mstatus, 8\nfence.i\ntail probe_main\n.previous");

enum {
  sda = HEXWALLET_SE051_I2C_SDA, scl = HEXWALLET_SE051_I2C_SCL,
  iso_reset = HEXWALLET_SE051_ISO7816_RST_N, nss = HEXWALLET_NFC_PIN_CS,
  sck = HEXWALLET_NFC_PIN_SCK, mosi = HEXWALLET_NFC_PIN_MOSI, miso = HEXWALLET_NFC_PIN_MISO,
  irq = HEXWALLET_NFC_PIN_IRQ, ven = HEXWALLET_NFC_PIN_VEN, download = HEXWALLET_NFC_PIN_DWL_REQ
};

static void select_pin(unsigned pin) {
  if (pin < SOC_RTCIO_PIN_COUNT) rtcio_ll_function_select(pin, RTCIO_LL_FUNC_DIGITAL);
  gpio_ll_output_disable(&GPIO, pin);
  gpio_ll_func_sel(&GPIO, pin, PIN_FUNC_GPIO);
  gpio_ll_input_enable(&GPIO, pin);
  gpio_matrix_out(pin, SIG_GPIO_OUT_IDX, false, false);
}

static void drive(unsigned pin, bool high) {
  gpio_ll_set_level(&GPIO, pin, high);
  gpio_ll_output_enable(&GPIO, pin);
}

static bool level(unsigned pin) { return gpio_ll_get_level(&GPIO, pin) != 0; }

// SCK stays low and VEN stays low during this check. Read the pads, not the
// output latches. Bit 1 is EINK_CS and bit 0 is SPI_NSS.
static uint8_t sample_selects() {
  ets_delay_us(5);
  return (level(HEXWALLET_EPD_PIN_CS) ? 2 : 0) | (level(nss) ? 1 : 0);
}

static void report(const char *text) {
  while (*text) {
    if (!usb_serial_jtag_ll_write_txfifo((const uint8_t *)text, 1)) {
      usb_serial_jtag_ll_txfifo_flush();
      ets_delay_us(50);
      continue;
    }
    ++text;
  }
  usb_serial_jtag_ll_txfifo_flush();
}

static void hex_byte(uint8_t value) {
  static const char digits[] = "0123456789abcdef";
  const char text[] = {digits[value >> 4], digits[value & 15], 0};
  report(text);
}

// Emulate open drain by driving only zero. Sample SCL on every rising edge
// so a held clock cannot be mistaken for a slave acknowledgement.
static void i2c_level(unsigned pin, bool release) {
  if (release) gpio_ll_output_disable(&GPIO, pin);
  else drive(pin, false);
  ets_delay_us(8);
}

static bool clock_high(void) {
  i2c_level(scl, true);
  for (unsigned n = 0; n < 1000; ++n) {
    if (level(scl)) return true;
    ets_delay_us(2);
  }
  return false;
}

static bool i2c_start(void) {
  i2c_level(sda, true);
  if (!clock_high() || !level(sda)) return false;
  i2c_level(sda, false);
  return !level(sda);
}

static bool i2c_write_byte(uint8_t value) {
  for (unsigned bit = 0x80; bit; bit >>= 1) {
    i2c_level(scl, false);
    i2c_level(sda, value & bit);
    if (!clock_high()) return false;
  }
  i2c_level(scl, false);
  i2c_level(sda, true);
  return clock_high() && !level(sda);
}

static bool i2c_read_byte(uint8_t &value, bool last) {
  value = 0;
  i2c_level(scl, false);
  i2c_level(sda, true);
  for (unsigned i = 0; i < 8; ++i) {
    if (!clock_high()) return false;
    value = (uint8_t)((value << 1) | level(sda));
    i2c_level(scl, false);
  }
  i2c_level(sda, last);
  return clock_high();
}

static bool i2c_stop(void) {
  i2c_level(scl, false);
  i2c_level(sda, false);
  clock_high();
  i2c_level(sda, true);
  return level(scl) && level(sda);
}

// Register pointer followed by repeated START, retaining the shared bus.
static bool camera_read_id_byte(uint8_t address, uint16_t reg, uint8_t &value) {
  bool ok = i2c_start() && i2c_write_byte(address << 1) &&
            i2c_write_byte(reg >> 8) && i2c_write_byte(uint8_t(reg));
  if (ok) {
    i2c_level(scl, false);
    ok = i2c_start() && i2c_write_byte((address << 1) | 1) && i2c_read_byte(value, true);
  }
  return i2c_stop() && ok;
}

static const char *probe_se(bool &ack, uint8_t &attempts) {
  while (attempts < 3) {
    ++attempts;
    if (!i2c_start()) return "I2C_BUS_HELD";
    const bool address_ack = i2c_write_byte(HEXWALLET_SE051_I2C_ADDRESS << 1);
    const bool scl_high = level(scl);
    if (!i2c_stop()) return "I2C_STOP_FAILED";
    if (!scl_high) return "I2C_CLOCK_TIMEOUT";
    if (address_ack) {
      ack = true;
      return "ACK";
    }
    if (attempts < 3) ets_delay_us(5000);
  }
  return "NACK";
}

// NXP UM11225 S-block interface reset; the CRC16/X-25 is sent LSB first.
// No application is selected and the response payload is never exported.
static uint16_t frame_crc(const uint8_t *data, unsigned count) {
  uint16_t crc = 0xffff;
  while (count--) {
    crc ^= *data++;
    for (unsigned i = 0; i < 8; ++i) crc = (crc >> 1) ^ ((crc & 1) ? 0x8408 : 0);
  }
  return crc ^ 0xffff;
}

static bool se_read(uint8_t *bytes, unsigned size) {
  bool ok = i2c_start() && i2c_write_byte((HEXWALLET_SE051_I2C_ADDRESS << 1) | 1);
  for (unsigned i = 0; ok && i < size; ++i) ok = i2c_read_byte(bytes[i], i + 1 == size);
  return i2c_stop() && ok;
}

static const char *probe_t1(uint8_t &length) {
  uint8_t request[] = {0x5a, 0xcf, 0, 0, 0};
  const uint16_t crc = frame_crc(request, 3);
  request[3] = (uint8_t)crc;
  request[4] = (uint8_t)(crc >> 8);
  bool sent = i2c_start() && i2c_write_byte(HEXWALLET_SE051_I2C_ADDRESS << 1);
  for (uint8_t byte : request) sent = sent && i2c_write_byte(byte);
  if (!i2c_stop() || !sent) return "RESET_WRITE_FAILED";
  uint8_t frame[260];
  bool received = false;
  for (unsigned attempt = 0; attempt < 100; ++attempt) {
    ets_delay_us(5000);
    if (!se_read(frame, 2)) continue;
    received = true;
    // Match the NXP transport's split reads. The start byte can appear
    // in either of the first two positions during NAD polling.
    if (frame[0] == 0xa5) {
      if (!se_read(frame + 2, 1)) return "RESET_HEADER_READ_FAILED";
    } else if (frame[1] == 0xa5) {
      frame[0] = 0xa5;
      if (!se_read(frame + 1, 2)) return "RESET_HEADER_READ_FAILED";
    } else {
      continue;
    }
    const unsigned total = 5u + frame[2];
    if (!se_read(frame + 3, total - 3)) return "RESET_READ_FAILED";
    if (frame_crc(frame, total - 2) != (frame[total-2] | (uint16_t(frame[total-1]) << 8))) return "BAD_CRC";
    if (frame[1] != 0xef) return "UNEXPECTED_PCB";
    length = frame[2];
    return "INTERFACE_RESET_OK";
  }
  return received ? "NO_RESPONSE_FRAME" : "I2C_READ_TIMEOUT";
}

static uint8_t spi_byte(uint8_t tx) {
  uint8_t rx = 0;
  for (unsigned bit = 0x80; bit; bit >>= 1) {
    gpio_ll_set_level(&GPIO, mosi, (tx & bit) != 0);
    ets_delay_us(1);
    gpio_ll_set_level(&GPIO, sck, 1);
    ets_delay_us(1);
    rx = (uint8_t)((rx << 1) | level(miso));
    gpio_ll_set_level(&GPIO, sck, 0);
  }
  return rx;
}

struct PanelProbe {
  bool reset_low, reset_high, busy_pullup, busy_pulldown, status_read;
  bool reset_pullup, reset_pulldown;
  bool reset_latch, reset_output, reset_gpio_route, reset_held;
  uint8_t outputs_low, outputs_high, status_pullup, status_pulldown;
};

// Sample only after releasing the output. A weak bias helps distinguish a
// floating input from a held level without extending a failed drive pulse.
static void sample_weak_bias(unsigned pin, bool &up, bool &down) {
  gpio_ll_output_disable(&GPIO, pin);
  gpio_ll_pulldown_dis(&GPIO, pin); gpio_ll_pullup_en(&GPIO, pin);
  ets_delay_us(1000); up = level(pin);
  gpio_ll_pullup_dis(&GPIO, pin); gpio_ll_pulldown_en(&GPIO, pin);
  ets_delay_us(1000); down = level(pin);
  gpio_ll_pulldown_dis(&GPIO, pin);
}

static bool panel_busy() {
  return level(HEXWALLET_EPD_PIN_BUSY) == HEXWALLET_EPD_BUSY_ACTIVE_LEVEL;
}

#if HEXWALLET_EPD_PROFILE == 0
// SSD1680 section 6.1.1: in a four-wire read the display drives the SDA
// contact used for MOSI. Keep PN7161 disabled and release SDA on turnaround.
static uint8_t read_panel_status(bool pullup) {
  constexpr unsigned cs = HEXWALLET_EPD_PIN_CS, dc = HEXWALLET_EPD_PIN_DC;
  if (pullup) gpio_ll_pullup_en(&GPIO, mosi);
  else gpio_ll_pulldown_en(&GPIO, mosi);
  drive(dc, false); drive(cs, false);
  for (unsigned bit = 0x80; bit; bit >>= 1) {
    drive(mosi, (0x2f & bit) != 0); ets_delay_us(2);
    drive(sck, true); ets_delay_us(2);
    if (bit == 1) {
      gpio_ll_output_disable(&GPIO, mosi);
      drive(dc, true);
    }
    drive(sck, false); ets_delay_us(2);
  }
  uint8_t status = 0;
  for (unsigned n = 0; n < 8; ++n) {
    drive(sck, true); ets_delay_us(2);
    status = uint8_t((status << 1) | level(mosi));
    drive(sck, false); ets_delay_us(2);
  }
  drive(cs, true);
  gpio_ll_pullup_dis(&GPIO, mosi); gpio_ll_pulldown_dis(&GPIO, mosi);
  return status;
}
#endif

static const char *probe_panel(PanelProbe &sample) {
  constexpr unsigned rst = HEXWALLET_EPD_PIN_RST, dc = HEXWALLET_EPD_PIN_DC;
  constexpr unsigned busy = HEXWALLET_EPD_PIN_BUSY, cs = HEXWALLET_EPD_PIN_CS;
  select_pin(busy); select_pin(dc); select_pin(rst);
  gpio_ll_set_output_enable_ctrl(&GPIO, rst, false, false);
  gpio_ll_od_disable(&GPIO, rst);
  // Check the driven pads locally while PN7161 is disabled. Test CS with
  // SCK idle, then deselect the display before changing the data lines.
  static constexpr unsigned outputs[] = {cs, dc, mosi, sck};
  for (unsigned i = 0; i < 4; ++i) {
    drive(outputs[i], false); ets_delay_us(5);
    if (level(outputs[i])) sample.outputs_low |= 1U << i;
    drive(outputs[i], true); ets_delay_us(5);
    if (level(outputs[i])) sample.outputs_high |= 1U << i;
  }
  drive(sck, false); drive(dc, false); drive(rst, true); ets_delay_us(200000);
  drive(rst, false); ets_delay_us(1000); sample.reset_low = level(rst);
  // Snapshot the state while low is requested, before releasing a failed pad.
  gpio_io_config_t cfg;
  gpio_ll_get_io_config(&GPIO, rst, &cfg);
  sample.reset_latch = (GPIO.out.val & (1u << rst)) != 0;
  sample.reset_output = cfg.oe && !cfg.oe_ctrl_by_periph && !cfg.oe_inv;
  sample.reset_gpio_route = cfg.ie && cfg.fun_sel == PIN_FUNC_GPIO && cfg.sig_out == SIG_GPIO_OUT_IDX &&
                            !GPIO.func_out_sel_cfg[rst].out_inv_sel && !cfg.od;
  sample.reset_held = gpio_ll_is_digital_io_hold(&GPIO, rst);
  if (sample.reset_low) {
    sample_weak_bias(rst, sample.reset_pullup, sample.reset_pulldown);
    gpio_ll_output_disable(&GPIO, dc);
    return "RESET_STUCK_HIGH";
  }
  ets_delay_us(9000); // Complete the application's 10 ms low pulse after the pad check.
  drive(rst, true); ets_delay_us(200000); sample.reset_high = level(rst);
  if (!sample.reset_high) {
    sample_weak_bias(rst, sample.reset_pullup, sample.reset_pulldown);
    gpio_ll_output_disable(&GPIO, dc);
    return "RESET_STUCK_LOW";
  }
  for (unsigned i = 0; i < 500 && panel_busy(); ++i) ets_delay_us(1000);
  const bool idle = !panel_busy();
  bool asserted = false;
  if (idle) {
    drive(cs, false); spi_byte(0x12); drive(cs, true);
    for (unsigned i = 0; i < 5000 && !asserted; ++i) { asserted = panel_busy(); ets_delay_us(2); }
    for (unsigned i = 0; i < 500 && panel_busy(); ++i) ets_delay_us(1000);
  }
  const bool final_busy = panel_busy();
#if HEXWALLET_EPD_PROFILE == 0
  if (idle && !final_busy) {
    sample.status_read = true;
    sample.status_pullup = read_panel_status(true);
    sample.status_pulldown = read_panel_status(false);
  }
#endif
  // BUSY stays an input. A line that follows both weak biases has no
  // strong driver at the MCU at the time of sampling.
  sample_weak_bias(busy, sample.busy_pullup, sample.busy_pulldown);
  gpio_ll_output_disable(&GPIO, rst);
  gpio_ll_output_disable(&GPIO, dc);
  if (!idle) return "BUSY_BEFORE_COMMAND";
  if (!asserted) return "NO_BUSY_EDGE";
  return final_busy ? "BUSY_TIMEOUT" : "SWRESET_BUSY_CYCLE";
}

typedef struct {
  uint8_t attempts, direction_reply, irq_at_start, irq_after_reset;
  uint8_t response[16], response_size, notification[32], notification_size;
  bool reset_ok, notified;
} NciProbe;

static unsigned read_nci(uint8_t packet[258]) {
  drive(nss, false);
  spi_byte(0xff);
  for (unsigned i = 0; i < 3; ++i) packet[i] = spi_byte(0xff);
  const unsigned size = 3u + packet[2];
  for (unsigned i = 3; i < size; ++i) packet[i] = spi_byte(0xff);
  drive(nss, true);
  ets_delay_us(100);
  return size;
}

static const char *probe_nfc(NciProbe *out) {
  uint8_t packet[258];
  out->irq_at_start = level(irq);
  // Drain startup notifications before issuing a command. Nothing from
  // power-on counts as the response to the host-initiated CORE_RESET.
  for (unsigned i = 0; level(irq) && i < 3; ++i) read_nci(packet);
  if (level(irq)) return "IRQ_STUCK_HIGH";
  if (!level(ven) || level(download) || !level(nss)) return "CONTROL_PIN_READBACK_FAILED";
  // NXP UM11495 4.3.3: selection wakes a sleeping NFCC. Retry the complete
  // frame after 5 ms when the first MISO byte does not announce readiness.
  while (out->attempts < 3) {
    ++out->attempts;
    if (level(irq)) return "IRQ_BEFORE_WRITE";
    drive(nss, false);
    if (level(nss)) { drive(nss, true); return "NSS_DRIVE_FAILED"; }
    out->direction_reply = spi_byte(0x00);
    if (out->direction_reply == 0xff) break;
    drive(nss, true);
    ets_delay_us(5000);
  }
  if (out->direction_reply != 0xff) return "SPI_DIRECTION_NOT_READY";
  const uint8_t reset[] = {0x20, 0x00, 0x01, 0x00}; // Keep controller configuration.
  for (unsigned i = 0; i < sizeof(reset); ++i) spi_byte(reset[i]);
  drive(nss, true);
  for (unsigned i = 0; i < 1200; ++i) {
    ets_delay_us(1000);
    if (!level(irq)) continue;
    out->irq_after_reset = 1;
    unsigned size = read_nci(packet);
    if (packet[0] == 0x40 && packet[1] == 0x00 && size >= 4) {
      out->response_size = size < sizeof(out->response) ? size : sizeof(out->response);
      for (unsigned j = 0; j < out->response_size; ++j) out->response[j] = packet[j];
      if (packet[3] != 0) return "NCI_RESET_REJECTED";
      out->reset_ok = true;
    } else if (packet[0] == 0x60 && packet[1] == 0 && packet[2] >= 5 && packet[3] == 0x02) {
      out->notification_size = size < sizeof(out->notification) ? size : sizeof(out->notification);
      for (unsigned j = 0; j < out->notification_size; ++j) out->notification[j] = packet[j];
      out->notified = true;
    }
    if (out->reset_ok && out->notified) return "CORE_RESET_OK";
  }
  return out->reset_ok ? "RESET_NOTIFICATION_TIMEOUT" : "RESET_RESPONSE_TIMEOUT";
}

extern "C" void probe_main(void) {
  static const unsigned nfc_pins[] = {nss, sck, mosi, miso, irq, ven, download, HEXWALLET_EPD_PIN_CS};
  uint8_t request = 0;
  ets_delay_us(100);
  while (request != '?' && request != 's') {
    usb_serial_jtag_ll_read_rxfifo(&request, 1);
    ets_delay_us(1000);
  }
  const bool test_nfc = request == '?';
  select_pin(sda);
  select_pin(scl);
  select_pin(iso_reset);
  drive(iso_reset, false);
  gpio_ll_pullup_en(&GPIO, sda);
  gpio_ll_pullup_en(&GPIO, scl);
  ets_delay_us(50000);
  bool se_ack = false;
  uint8_t se_attempts = 0;
  const char *se = probe_se(se_ack, se_attempts);
  uint8_t t1_length = 0;
  const char *t1 = se_ack ? probe_t1(t1_length) : "SKIPPED";
  uint8_t camera_addr = 0, id_high = 0, id_low = 0;
  if (test_nfc) {
    for (uint8_t addr : hexwallet::kOv9281Addresses) {
      uint8_t high, low;
      if (!camera_read_id_byte(addr, hexwallet::kOv9281ChipIdHighRegister, high) ||
          !camera_read_id_byte(addr, hexwallet::kOv9281ChipIdLowRegister, low)) continue;
      camera_addr = addr;
      id_high = high;
      id_low = low;
      if (((high << 8) | low) == hexwallet::kOv9281ChipId) break;
    }
  }
  gpio_ll_pullup_dis(&GPIO, sda);
  gpio_ll_pullup_dis(&GPIO, scl);
  NciProbe nci = {0};
  const char *nfc = "SKIPPED";
  const char *panel = "SKIPPED";
  PanelProbe panel_sample{};
  uint8_t idle_cs = 0xff, display_cs = 0xff, nfc_cs = 0xff, released_cs = 0xff;
  bool selects_ok = false;
  if (test_nfc) {
    for (unsigned pin : nfc_pins) select_pin(pin);
    drive(HEXWALLET_EPD_PIN_CS, true);
    drive(nss, true);
    drive(sck, false);
    drive(mosi, false);
    drive(download, false);
    drive(ven, false);
    ets_delay_us(15000);
    idle_cs = sample_selects();
    if (idle_cs == 3) {
      drive(HEXWALLET_EPD_PIN_CS, false);
      display_cs = sample_selects();
      drive(HEXWALLET_EPD_PIN_CS, true);
    }
    if (display_cs == 1 && sample_selects() == 3) {
      drive(nss, false);
      nfc_cs = sample_selects();
      drive(nss, true);
    }
    released_cs = sample_selects();
    selects_ok = idle_cs == 3 && display_cs == 1 && nfc_cs == 2 && released_cs == 3;
    if (selects_ok) {
      drive(ven, true);
      ets_delay_us(50000);
      nfc = probe_nfc(&nci);
      drive(ven, false);
      drive(nss, true);
      panel = probe_panel(panel_sample);
    } else {
      panel = nfc = "CS_READBACK_FAILED";
    }
    for (unsigned pin : nfc_pins) gpio_ll_output_disable(&GPIO, pin);
  }
  // Reading the same cached result again does not issue another command.
  for (;;) {
    if (request == '?' || request == 's') {
      report("HEXWALLET RAM PROBE\r\nSE_I2C_48="); report(se);
      report(" attempts="); hex_byte(se_attempts);
      report(" T1="); report(t1); report(" info_len_hex="); hex_byte(t1_length);
      report("\r\nPN7161_NCI="); report(nfc);
      report(" attempts="); hex_byte(nci.attempts);
      report(" dir="); hex_byte(nci.direction_reply);
      report(" irq_start="); hex_byte(nci.irq_at_start);
      report(" irq_after="); hex_byte(nci.irq_after_reset);
      report(" rsp="); for (unsigned j = 0; j < nci.response_size; ++j) hex_byte(nci.response[j]);
      report(" ntf="); for (unsigned j = 0; j < nci.notification_size; ++j) hex_byte(nci.notification[j]);
      if (test_nfc) {
        report("\r\nCS_GPIO idle/panel/nfc/idle="); hex_byte(idle_cs); hex_byte(display_cs);
        hex_byte(nfc_cs); hex_byte(released_cs);
        report("\r\nPANEL="); report(panel);
        report(" profile="); hex_byte(HEXWALLET_EPD_PROFILE);
        report(" busy_active="); hex_byte(HEXWALLET_EPD_BUSY_ACTIVE_LEVEL);
        if (panel_sample.reset_low) report(" rst_low=01");
        else if (selects_ok) {
          report(" rst_low/high="); hex_byte(panel_sample.reset_low); hex_byte(panel_sample.reset_high);
          if (panel_sample.reset_high) {
            report(" busy_pullup/pulldown="); hex_byte(panel_sample.busy_pullup); hex_byte(panel_sample.busy_pulldown);
          }
        }
        if (selects_ok) {
          report(" rst_latch/oe/gpio/hold="); hex_byte(panel_sample.reset_latch); hex_byte(panel_sample.reset_output);
          hex_byte(panel_sample.reset_gpio_route); hex_byte(panel_sample.reset_held);
          if (panel_sample.reset_low || !panel_sample.reset_high) {
            report(" released_rst_pullup/pulldown=");
            hex_byte(panel_sample.reset_pullup); hex_byte(panel_sample.reset_pulldown);
          }
          report(" cs_dc_mosi_sck_low/high="); hex_byte(panel_sample.outputs_low); hex_byte(panel_sample.outputs_high);
        }
        if (panel_sample.status_read) {
          report(" status_2f_pullup/pulldown="); hex_byte(panel_sample.status_pullup); hex_byte(panel_sample.status_pulldown);
        }
        report("\r\nCAMERA_SCCB=");
        if (camera_addr) {
          hex_byte(camera_addr); report(" chip_id="); hex_byte(id_high); hex_byte(id_low);
        } else report("NO_COMPLETE_ID");
      }
      report("\r\nEND RAM PROBE\r\n");
    }
    request = 0;
    usb_serial_jtag_ll_read_rxfifo(&request, 1);
    ets_delay_us(1000);
  }
}
