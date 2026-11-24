#include "CameraBackup.h"
#include "WalletBoardPins.h"

#if defined(ARDUINO_ARCH_ESP32) && defined(CONFIG_IDF_TARGET_ESP32P4) && defined(HEXWALLET_CAMERA_SCCB_SDA) && defined(HEXWALLET_CAMERA_DPHY_LDO_CHANNEL)
#include "WalletBoardPort.h"
#include "WalletSecurity.h"
#include "WalletWorker.h"
#include "CameraDecode.h"
#include <atomic>
#include <cstring>
#include <initializer_list>
#include <driver/isp_core.h>
#include <esp_cam_ctlr.h>
#include <esp_cam_ctlr_csi.h>
#include <esp_cam_sensor.h>
#include <esp_cache.h>
#include <esp_ldo_regulator.h>
#include <esp_sccb_intf.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <ov9281.h>
extern "C" {
#include <esp_sccb_i2c.h>
}

namespace hexwallet {
namespace {
constexpr size_t width = 640, height = 400, pixels = width * height;
bool active;
std::atomic<bool> cancelled{false};
CameraRead outcome;
char result[65];

struct Capture {
  esp_sccb_io_handle_t io{};
  esp_cam_sensor_device_t *sensor{};
  esp_ldo_channel_handle_t ldo{};
  isp_proc_handle_t isp{};
  esp_cam_ctlr_handle_t csi{};
  SemaphoreHandle_t done{};
  uint8_t *frame{}, *discard{};
  unsigned transfers{};
  std::atomic<bool> bad_frame{false};
  bool enabled{}, started{}, stream_attempted{};

  ~Capture() {
    int off = 0;
    if (stream_attempted) esp_cam_sensor_ioctl(sensor, ESP_CAM_SENSOR_IOC_S_STREAM, &off);
    if (started) esp_cam_ctlr_stop(csi);
    if (enabled) esp_cam_ctlr_disable(csi);
    if (csi) esp_cam_ctlr_del(csi);
    if (isp) esp_isp_del_processor(isp);
    if (ldo) esp_ldo_release_channel(ldo);
    if (sensor) esp_cam_sensor_del_dev(sensor);
    if (io) esp_sccb_del_i2c_io(io);
    if (done) vSemaphoreDelete(done);
    for (auto *buffer : {frame, discard}) {
      if (buffer) { secure_zero(buffer, pixels); heap_caps_free(buffer); }
    }
  }
};

bool next_buffer(esp_cam_ctlr_handle_t, esp_cam_ctlr_trans_t *trans, void *context) {
  auto &capture = *static_cast<Capture *>(context);
  // First and subsequent frames go to a sink. DMA writes the sample exactly once.
  trans->buffer = capture.transfers == 1 ? capture.frame : capture.discard;
  if (capture.transfers < 2) ++capture.transfers;
  trans->buflen = pixels;
  return false;
}

bool frame_done(esp_cam_ctlr_handle_t, esp_cam_ctlr_trans_t *trans, void *context) {
  auto &capture = *static_cast<Capture *>(context);
  if (trans->buffer != capture.frame) return false;
  if (trans->received_size != pixels) capture.bad_frame.store(true);
  BaseType_t woken = pdFALSE;
  xSemaphoreGiveFromISR(capture.done, &woken);
  return woken == pdTRUE;
}

bool frame_error(esp_cam_ctlr_handle_t, const esp_cam_ctlr_error_event_data_t *, void *context) {
  static_cast<Capture *>(context)->bad_frame.store(true);
  return false;
}

CameraRead capture_frame(Capture &c) {
  CameraInfo id{};
  i2c_master_bus_handle_t bus{};
  if (board_camera_probe(&id) != CameraProbeState::PresentUnverified ||
      i2c_master_get_bus_handle(1, &bus) != ESP_OK) return CameraRead::Unavailable;
  sccb_i2c_config_t control{};
  control.device_address = id.sccb_address;
  control.dev_addr_length = I2C_ADDR_BIT_LEN_7;
  control.scl_speed_hz = 100000;
  control.addr_bits_width = 16;
  control.val_bits_width = 8;
  if (sccb_new_i2c_io(bus, &control, &c.io) != ESP_OK) return CameraRead::Unavailable;
  esp_cam_sensor_config_t sensor_cfg{};
  sensor_cfg.sccb_handle = c.io;
  sensor_cfg.sensor_port = ESP_CAM_SENSOR_MIPI_CSI;
  sensor_cfg.xclk_pin = sensor_cfg.reset_pin = sensor_cfg.pwdn_pin = GPIO_NUM_NC;
  c.sensor = ov9281_detect(&sensor_cfg);
  esp_cam_sensor_format_t mode{};
  if (!c.sensor || esp_cam_sensor_set_format(c.sensor, nullptr) != ESP_OK ||
      esp_cam_sensor_get_format(c.sensor, &mode) != ESP_OK || mode.width != width ||
      mode.height != height || mode.mipi_info.lane_num != 2 || mode.format != ESP_CAM_SENSOR_PIXFORMAT_RAW8)
    return CameraRead::Unavailable;
  esp_ldo_channel_config_t phy{};
  static_assert(HEXWALLET_CAMERA_DPHY_LDO_CHANNEL == 3 || HEXWALLET_CAMERA_DPHY_LDO_CHANNEL == 4,
                "The camera D-PHY requires a dedicated peripheral LDO");
  phy.chan_id = HEXWALLET_CAMERA_DPHY_LDO_CHANNEL;
  phy.voltage_mv = 2500;
  if (esp_ldo_acquire_channel(&phy, &c.ldo) != ESP_OK) return CameraRead::Frame;
  esp_cam_ctlr_csi_config_t rx{};
  rx.h_res = width;
  rx.v_res = height;
  rx.data_lane_num = mode.mipi_info.lane_num;
  rx.lane_bit_rate_mbps = mode.mipi_info.mipi_clk / 1000000;
  rx.queue_items = 1;
  rx.input_data_color_type = rx.output_data_color_type = CAM_CTLR_COLOR_RAW8;
  rx.bk_buffer_dis = true;
  if (esp_cam_new_csi_ctlr(&rx, &c.csi) != ESP_OK) return CameraRead::Frame;
  esp_isp_processor_cfg_t raw{};
  raw.clk_src = ISP_CLK_SRC_DEFAULT;
  raw.clk_hz = 240000000;
  raw.input_data_source = ISP_INPUT_DATA_SOURCE_CSI;
  raw.input_data_color_type = raw.output_data_color_type = ISP_COLOR_RAW8;
  raw.h_res = width;
  raw.v_res = height;
  raw.has_line_start_packet = raw.has_line_end_packet = mode.mipi_info.line_sync_en;
  raw.flags.bypass_isp = true;
  if (esp_isp_new_processor(&raw, &c.isp) != ESP_OK) return CameraRead::Frame;
  c.done = xSemaphoreCreateBinary();
  constexpr uint32_t caps = MALLOC_CAP_SPIRAM | MALLOC_CAP_DMA | MALLOC_CAP_CACHE_ALIGNED;
  c.frame = static_cast<uint8_t *>(esp_cam_ctlr_alloc_buffer(c.csi, pixels, caps));
  c.discard = static_cast<uint8_t *>(esp_cam_ctlr_alloc_buffer(c.csi, pixels, caps));
  if (!c.done || !c.frame || !c.discard) return CameraRead::Memory;
  esp_cam_ctlr_evt_cbs_t events{};
  events.on_get_new_trans = next_buffer;
  events.on_trans_finished = frame_done;
  events.on_error = frame_error;
  if (esp_cam_ctlr_register_event_callbacks(c.csi, &events, &c) != ESP_OK ||
      esp_cam_ctlr_enable(c.csi) != ESP_OK) return CameraRead::Frame;
  c.enabled = true;
  if (esp_cam_ctlr_start(c.csi) != ESP_OK) return CameraRead::Frame;
  c.started = true;
  int on = 1;
  c.stream_attempted = true;
  if (esp_cam_sensor_ioctl(c.sensor, ESP_CAM_SENSOR_IOC_S_STREAM, &on) != ESP_OK ||
      xSemaphoreTake(c.done, pdMS_TO_TICKS(750)) != pdTRUE || c.bad_frame.load()) return CameraRead::Frame;
  return esp_cache_msync(c.frame, pixels, ESP_CACHE_MSYNC_FLAG_DIR_M2C) == ESP_OK ? CameraRead::Ready : CameraRead::Frame;
}

void run(void *) {
  Capture capture;
  outcome = cancelled.load() ? CameraRead::Cancelled : capture_frame(capture);
  if (outcome == CameraRead::Ready && !cancelled.load())
    outcome = camera_decode_backup(capture.frame, width, height, result);
  if (cancelled.load() || outcome != CameraRead::Ready) secure_zero(result, sizeof(result));
}
}

CameraRead camera_backup_start() {
  if (active || (!wallet_worker_ready() && !wallet_worker_start())) return CameraRead::Busy;
  cancelled.store(false);
  if (!wallet_worker_begin(run, nullptr)) return CameraRead::Busy;
  active = true;
  return CameraRead::Pending;
}
void camera_backup_cancel() { if (active) cancelled.store(true); }
bool camera_backup_take(CameraRead &status, char (&key)[65]) {
  if (!active || !wallet_worker_wait(0)) return false;
  status = cancelled.load() ? CameraRead::Cancelled : outcome;
  if (status == CameraRead::Ready) memcpy(key, result, sizeof(result));
  else secure_zero(key, sizeof(key));
  secure_zero(result, sizeof(result));
  active = false;
  return true;
}
}
#else
namespace hexwallet {
CameraRead camera_backup_start() { return CameraRead::Unavailable; }
void camera_backup_cancel() {}
bool camera_backup_take(CameraRead &, char (&)[65]) { return false; }
}
#endif
