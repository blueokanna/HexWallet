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

An I²C ACK at `0x48` shows that a device answered the address. `INTERFACE_RESET_OK` requires a T=1 response with the expected PCB and a valid CRC. Neither identifies the secure element SKU. For NFC, `SPI_DIRECTION_NOT_READY` gives the byte sampled on MISO and the number of selection attempts. `CORE_RESET_OK` requires both a successful NCI response and the matching reset notification. RF and tag reading require a separate test.
