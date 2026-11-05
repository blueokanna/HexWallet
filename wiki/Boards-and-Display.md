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
| 6 | Headless | none | none | Serial CLI; signing needs the host-only compile flag |
| 7 | HexWallet P4 rev A | 128×296 SSD1680, SPI | 4 keys (SW1–SW4) | SE051C2HQ1 on I²C, PN7161 on the shared SPI bus |

Board 7 comes from the EasyEDA project `c26102103`; each pin comment names the package pad, so the
GPIO column can be re-derived from the P4 datasheet before first power-on. The panel and the PN7161
share SCK/MOSI/MISO and use separate chip selects.

## E-paper profiles

A 2.9-inch diagonal is not a protocol. The P4 board selects an explicit profile:

| `HEXWALLET_EPD_PROFILE` | Panel | Refresh |
| --- | --- | --- |
| 0 (default) | SSD1680 mono 128×296 | full refresh; partial uses the controller's OTP waveform |
| 1 | SSD1683-class four-colour 128×296 | 2bpp, full refresh only, BUSY active low |
| 2 | SSD1680 mono V2 | partial uses OTP, BUSY active high |

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

The approval barrier is released only after the refresh succeeds. A BUSY timeout or SPI failure
never counts as "the transaction was displayed".

## Camera

The OV9281 is a MIPI CSI-2 sensor with an SCCB control bus. Only the control side exists:
`camera_probe()` reads the chip-id registers and returns one of four states —
`NotConfigured`, `NoResponse`, `WrongSensor`, `PresentUnverified`. There is no "supported" state.

On rev A the camera is **not connected**: the CSI pads run to series resistors with nothing on the
other side, and the camera FPC has no nets. `HEXWALLET_CAMERA_*` is therefore undefined and the
probe returns `NotConfigured`. A later revision only needs the SCCB pins in the board profile for
the probe; CSI streaming still needs the vendor register table, which is not in the tree and will
not be invented.

## QR codes

`QrCode.cpp` is an in-tree encoder and 1bpp renderer: byte mode, versions 1–10 (21×21…57×57), ECC
levels L/M/Q/H, up to 271 bytes, no truncation. The wallet policy walks H → Q → M and never asks
for L; if M does not fit, the screen shows text instead of a symbol.

The self-test decodes its own output (format information, unmasking, de-interleaving, RS syndromes,
byte-exact payload). That proves self-consistency, not scannability. A separate host check compares
every version/level/mask matrix against nayuki/QR-Code-generator at a pinned commit — a transposed
format-information half would pass a self-test and fail a phone.

## UI assets

- `CoinIcons` — 32×32 1bpp marks packed from CC0 artwork; no image decoder in flash.
- `Mascot` / `MaidSprite` — sprite animation for the review screen; frames are packed by
  `tools/pack_maid_sprite.ps1`.
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
