# Boards and display

[中文](Boards-and-Display-zh) · [Home](Home)

Pin maps live in `WalletBoardPins.h`, one block per board, each taken from a schematic or a vendor
pinout. Nothing is inferred from a board name.

## Boards

| Id | Board | Panel | Input | Notes |
| --- | --- | --- | --- | --- |
| 1 | LilyGO T-Display S3 AMOLED | 240×536 RM67162, SPI | CST816S touch | ESP32-S3, default profile |
| 2 | T-Display S3 AMOLED Plus | same | CST816S | AXP313A PMU, microSD on a second SPI bus |
| 3 | T-Display S3 | 170×320 ST7789, 8-bit parallel | CST816S | `HEXWALLET_PIN_POWER_ON` must be high before the panel works |
| 4 | T-Deck Max | 240×320 GDEQ031T10 / UC8253, SPI | none verified | BOOT is the only usable key; touch sits behind an XL9555 and is not wired |
| 5 | T-Echo Lite Kit | 176×192, SPI | TCA8418 keyboard | nRF52840 pin map only; no nRF52 build target in this tree |
| 6 | Headless | none | BOOT: S3 GPIO0, P4 GPIO35 | Serial CLI; approval without a trusted local display is refused by default |
| 7 | HexWallet P4 rev A | 296×128 landscape, SSD1680 SPI | OK, Previous, Next, Back | SE051C2HQ1 on I²C, PN7161 on the shared SPI bus |

Board 7 comes from the EasyEDA project `c26102103`; each pin comment names the package pad, so the
GPIO column can be re-derived from the P4 datasheet before first power-on. The panel and the PN7161
share GPIO7 (SCK) and GPIO8 (MOSI). GPIO9 (MISO) connects only to the PN7161. The panel uses EINK_CS on GPIO16 (FPC pin 12). The PN7161 uses SPI_NSS on GPIO13 (U3 pin 1) at 1 MHz. Both selects are active low. The drivers share one SPI instance and read back both select pads under the transaction lock before clocking data. A FreeRTOS task waits for the panel's BUSY line with SPI released, allowing NFC transactions between display transfers. The monochrome path converts the byte-aligned bounds of LVGL changes, skips identical frames and puts the panel to sleep after 30 seconds without a changed frame.

On the supplied rev A PCB, USB1 D− and D+ reach U1 package pads 24 and 25 on the `DM` and `DP` nets. The U1 symbol maps these pads to GPIO22 and GPIO23. The P4's default USB Serial/JTAG PHY uses GPIO24/GPIO25, and its high-speed PHY uses package pads 49/50. Neither pair is wired to USB1. Native USB enumeration or ROM USB flashing through this connector requires a board wiring change. [Espressif USB PHY assignments](https://docs.espressif.com/projects/esp-iot-solution/en/latest/usb/usb_overview/usb_phy.html)

The `TX` and `RX` board pads reach the ROM UART0 pins, U1 pads 69 (GPIO37) and 70 (GPIO38), respectively. Use a common ground and cross TX/RX with a 3.3 V logic-level serial adapter. Switch designators `SW1` and `SW2` connect to EN and the GPIO35 boot strap. The four application buttons have different designators (`按键1` through `按键4`) and use the net names `SW1` through `SW4`. [Espressif hardware design guidelines](https://docs.espressif.com/projects/esp-hardware-design-guidelines/en/latest/esp32p4/schematic-checklist-esp32p4.html)

## E-paper profiles

The gallery contains 66 states and 132 individual 296 × 128 PNGs, rendered with host LVGL 9.5.0 and the firmware's panel conversion. The HTML view filters by language. The audit identifies each firmware artifact and lists outstanding physical measurements. [Bilingual gallery](UI-Gallery) · [HTML gallery](ui-gallery/index.html) · [UI audit](UI-Audit-2026-11-24)

A 2.9-inch diagonal is not a protocol. The P4 board selects an explicit profile:

| `HEXWALLET_EPD_PROFILE` | Panel | Refresh |
| --- | --- | --- |
| 0 (default) | SSD1680 mono 128×296 | full refresh; partial uses the controller's OTP waveform |
| 1 | SSD1683-class four-colour 128×296 | 2bpp, full refresh only, BUSY active low |
| 2 | SSD1680 mono V2 | partial uses OTP, BUSY active high |
| 3 | HINK-E029A01 mono 128×296 (SSD1608/IL3820-family commands) | 2 MHz SPI, room-temperature OTP full refresh; BUSY low per A/0 manual |
| 4 | E029A01N16C355 with E029A01-FPC-A1, 128×296 mono | 2 MHz SPI, 25 °C OTP full refresh, 30-byte family reference partial waveform, BUSY low per supplied A/0 manual |

Select profile 3 with `tools/build_p4_board.ps1 -HinkE029A01` for a HINK-E029A01 panel.
The COM6 8 MiB USB Serial/JTAG assembly also needs `-FlashSizeMiB 8 -UsbSerialJtag`.
HINK uses `0x12` for software reset, `0x24` for 1bpp RAM and `0x20` for activation.
The Waveshare G four-colour manual does not apply. Profile 3 writes 25 C through `0x1A`
because the board has no external panel temperature sensor, then uses `0x22=0xDF` to load
OTP, perform a full refresh and shut down the pump without reading the absent sensor.
This is a room-temperature bring-up configuration; other temperatures need validation.
It omits SSD1680's `0x18` internal sensor selection, two-byte `0x21`, and `0x26` old RAM writes.

The HINK A/0 manual specifies BUSY low, while the GDEH029A1 / GxEPD2_290 driver uses high.
After checking the fitted panel, `-EpdBusyActiveLevel 1` (or the build macro
`HEXWALLET_EPD_BUSY_ACTIVE_LEVEL=1`) selects high explicitly; firmware logs the selection.
The complete marking `E029A01N16C355` has no independently verified datasheet here.
Its suffix alone does not establish polarity, OTP contents or waveform compatibility.
HINK's host LUT is 30 bytes; profile 3 currently supports full refresh only and rejects
SSD1680's 159-byte partial waveform.

Select profile 4 with `-E029A01N16C355`. The first frame after boot or wake uses a full refresh and seeds both RAM banks. Small changes use a byte-aligned window and the Waveshare V1 2.9-inch monochrome differential waveform. After activation and a completed BUSY cycle the driver writes the same window to the other bank. The board schedules a full refresh after eight partial updates. On COM6 the reinserted panel's RESET still reads high when driven low. BUSY polarity and visible full/partial refresh remain unverified on this assembly. [Reference waveform](https://github.com/waveshareteam/e-Paper/blob/master/Arduino/epd2in9/epd2in9.cpp)

For the 24-pin FPC, align pin 1 with the C47 end of the socket. With respect to pin 17 (ground), verify the supply on pins 15 (VDDIO) and 16 (VCI). Pin 8 is grounded for 4-wire SPI. GPIO17 drives pin 10 (RES#); GPIO18 samples pin 9 (BUSY). The driver preloads RES# high, waits 200 ms, drives low for 10 ms, then drives high for 200 ms and checks for idle BUSY (high) before software reset `0x12`. These delays are driver settings. The manual specifies the electrical levels and order on pages 8, 18 and 23. At VDDIO = 3.3 V a scope at the pin 10 solder joint should show ≤0.66 V while asserted and ≥2.64 V after release. A successful visible frame also requires BUSY to go low during activation and return high.

References: [HINK A/0 manufacturer manual mirror](https://github.com/ieiao/hanshow-2in9-epaper/blob/master/docs/HINK-E029A01-0629.pdf),
[HINK hardware demo](https://github.com/ieiao/hanshow-2in9-epaper),
[Zephyr E029A01 / SSD1608 mapping](https://github.com/zephyrproject-rtos/zephyr/blob/main/boards/shields/waveshare_epaper/doc/index.rst).

Rules the driver enforces:

- A board that needs a tuned waveform defines a 159-byte `HEXWALLET_EPD_PARTIAL_LUT`; the first 153
  bytes go to `0x32`, followed by EOPT, VGH, VSH1/VSH2/VSL and VCOM. A waveform table without the
  voltage settings is rejected — that is the usual cause of ghosting.
- Four-colour mode requires `HEXWALLET_EPD_COLOR_INIT`, an explicit register table. Without it
  `begin()` fails and prints `ERR: e-paper panel did not initialise`; it does not fall back to a
  grey-looking screen.
- Full refresh establishes the old/new RAM baseline; partial refresh syncs the old frame afterwards.
  The first update, or exhaustion of the eight-partial budget, forces a full refresh. Partial
  windows must be byte-aligned.
- Mono frames use 1 = black and are inverted for the SSD1680 RAM. A transfer failure invalidates the
  panel state instead of leaving a half-updated screen.
- Refresh timeouts are 45 s full / 4 s partial. That is a failure bound, not a measured refresh time.

The approval barrier is released only after refresh succeeds. A reset readback failure stops
initialization and releases the reset output. BUSY must assert and then return idle. Failed reset,
missing BUSY activity, timeout or SPI failure cannot release the approval barrier.

With the display on the left and the bottom-side application keys facing the viewer, the PCB maps left to right to OK (GPIO30), Previous (GPIO31), Next (GPIO32) and Back (GPIO33). Previous and Next scroll long fields. OK selects Reject first. Select Approve and hold OK for 750 ms to authorize. Back rejects directly. A long press on the independent BOOT switch (GPIO35) controls USB data at runtime. Physical mounting awaits verification.

Board initialization owns `lv_init()`, the LVGL 9 millisecond callback, the display and the keypad group. E-paper retains a native RGB565 framebuffer; color panels use `RGB565_SWAPPED` wire buffers. Global byte swapping is disabled so partial redraws cannot mutate retained pixels. Initialization failures release allocated display resources before a retry.

## Camera

The OV9281 connector shares GPIO10/11 with U2 and the RTC. FPC pads 2 and 3 carry SDA and SCL. The CSI clock and both data pairs connect through R32–R37. A USB-loaded SRAM probe on COM6 read chip ID `0x9281` at 7-bit address `0x60`.

The camera decoder accepts a 640 × 400 RAW8 frame. A synthetic BIP38 image reached the network selector in host tests. The c26102103 PCB connects U1 pin 73 (`VDDO_3`) to the 1.8 V PSRAM inputs. Board 7 therefore disables the camera's 2.5 V D-PHY supply request and reports capture unavailable. [Pin mapping and COM6 readback](validation.md#com6-bring-up)

## QR codes

`QrCode.cpp` is an in-tree encoder and 1bpp renderer: byte mode, versions 1–10 (21×21…57×57), ECC
levels L/M/Q/H, up to 271 bytes, no truncation. The wallet policy walks H → Q → M and never asks
for L; if M does not fit, the screen shows text instead of a symbol.

The self-test decodes its own output (format information, unmasking, de-interleaving, RS syndromes,
byte-exact payload). That proves self-consistency, not scannability. A separate host check compares
every version/level/mask matrix against nayuki/QR-Code-generator at a pinned commit — a transposed
format-information half would pass a self-test and fail a phone.

The receive QR stays on the left in landscape and at the top in portrait while the details scroll. Rendering uses integer pixels per module and a four-module quiet zone. ZXing recovered the complete fixture ETH address from both languages at native size, at 148×64, and at 222×96 with a 0.4-pixel Gaussian blur. Physical reading distance depends on optics and screen reflections. [UI gallery](UI-Gallery.md)

## UI assets

- `CoinIcons` compiles 166 source images into 32×32 monochrome bitmaps. Network aliases reuse artwork. The catalog test checks the symbol for every one of its 214 entries. [Artwork and digests](../assets/icons/sources.json)
- The DeepSeek companion roams on its own page and responds to feeding, petting and play. E-paper animation waits for the display and pauses after 30 seconds of inactivity. P4 uses PIE for aligned sprite copies and PPA with 2D DMA for larger monochrome updates. A pixel-by-pixel rotation check runs at initialization. A failed check or transfer selects the CPU renderer.
- LVGL 9.5.0 with `lv_conf.h` in the sketch root. `LV_CONF_INCLUDE_SIMPLE` must be defined or LVGL
  ignores it and the widgets the UI uses are not compiled in.

## Licensing note

Board 4 links GxEPD2, which is GPL-3.0. That is a real conflict with the non-commercial license in
`LICENSE`: a board-4 image is a combined work and would have to satisfy GPL-3.0. The P4 path does not
have this problem because it uses the in-tree SSD1680 driver. See `NOTICE`.

## Not validated

Full-refresh timing on a cold panel, four-colour analogue settings, partial-refresh ghosting over
many cycles, BUSY behaviour at low temperature, sleep/wake recovery, and the PN7161 RF path all
need a bench session on the actual board. Compiling the driver is not testing the panel.
