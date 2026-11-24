# Board 7 SRAM probe

The ESP32-P4 ROM loads this probe into internal SRAM over USB Serial/JTAG. It uses the board 7 pin map and the ROM symbols for P4 revisions v3.1–v3.99. Reset or loss of power ends the session. No flash or PSRAM is required. The probe sends no wallet APDUs and does not read or write credentials.

On Windows, point `$espTools` at the Arduino-ESP32 3.3.13 package's `tools` directory. These commands query the secure element address and, on ACK, request a T=1 interface reset.

```powershell
$espTools = "$env:LOCALAPPDATA/Arduino15/packages/esp32/tools"
./tools/p4_ram_probe/build.ps1 -EspTools $espTools
& "$espTools/esptool_py/5.3.1/esptool.exe" --chip esp32p4 -p COM6 --before usb-reset --no-stub load-ram build/p4-ram-probe/probe.bin
./tools/p4_ram_probe/read.ps1 -Port COM6 -SecureElementOnly
```

To also check a powered PN7161, omit `-SecureElementOnly` on the first read after loading the probe. The probe selects normal NCI mode, cycles VEN, and checks SPI readiness before sending CORE_RESET with configuration retention. Subsequent reads return the cached report. Reload the probe for a fresh test.

The full probe checks both active-low selects with SCK and PN7161 VEN low. `CS_GPIO idle/panel/nfc/idle=03010203` means the MCU read both pads high, only EINK_CS low, only SPI_NSS low, then both high. Bit 1 represents EINK_CS and bit 0 represents SPI_NSS. `ff` marks a skipped sample. Probe FPC pin 12 and PN7161 pin 1 to check the signals at the receiving devices.

The probe skips both SPI protocols if the CS check fails. With selects working, it exercises PN7161 and then checks panel RESET with PN7161 disabled. If RESET fails to follow the output, the probe releases the pin and reports `released_rst_pullup/pulldown`. Each byte is the digital level under the corresponding weak bias. For example, `0101` means that the pin read high under both biases. These samples are taken at the MCU. The probe also reads OV9281 ID registers `0x300a/0x300b` on GPIO10/11.

For a HINK-E029A01 run the following sequence. Its profile uses active-low BUSY and the HINK software reset. An observed BUSY cycle measures the response to reset. Visible refresh still requires an application frame.

```powershell
./tools/p4_ram_probe/build.ps1 -EspTools $espTools -HinkE029A01
& "$espTools/esptool_py/5.3.1/esptool.exe" --chip esp32p4 -p COM6 --before usb-reset --no-stub load-ram build/p4-ram-probe-hink/probe.bin
./tools/p4_ram_probe/read.ps1 -Port COM6
```

For the `E029A01N16C355` reference configuration, use `-E029A01N16C355` and `build/p4-ram-probe-n16c355/probe.bin`. The report shows `profile=04` and the configured BUSY level. A failed RESET exits before the software-reset command or any BUSY-cycle measurement.

`rst_latch/oe/gpio/hold` gives four bytes sampled while driving RES# low. `00010100` means the output latch is low, GPIO controls the enabled output, the pad uses the non-inverted push-pull GPIO route with input enabled, and the individual pad hold is clear. Compare `rst_low` with this snapshot. The pin 10 voltage at the display connector needs a separate measurement.

An I²C ACK at `0x48` shows that a device answered the address. `INTERFACE_RESET_OK` requires a T=1 response with the expected PCB and a valid CRC. Neither identifies the secure element SKU. For NFC, `SPI_DIRECTION_NOT_READY` gives the byte sampled on MISO and the number of selection attempts. `CORE_RESET_OK` requires both a successful NCI response and the matching reset notification. RF and tag reading require a separate test.
