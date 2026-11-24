param(
  [string]$Port = 'COM6',
  [string]$Esptool = "$PSScriptRoot/../build/board-sdk-3.3.13/data/packages/esp32/tools/esptool_py/5.3.1/esptool.exe",
  [string]$VerifyBuild,
  [switch]$StayInBootloader
)
$ErrorActionPreference = 'Stop'
$Esptool = (Resolve-Path -LiteralPath $Esptool).Path

function Invoke-Rom([string[]]$Command, [string]$Before = 'no-reset', [string]$After = 'no-reset') {
  # Windows can list the native USB port before its device handle is available.
  # Retry only the initial identity read if esptool could not open that port.
  $ErrorActionPreference = 'Continue'
  $attempts = if ($Before -eq 'usb-reset' -and $Command[0] -eq 'read-mac') { 5 } else { 1 }
  for ($attempt = 1; $attempt -le $attempts; $attempt++) {
    $reply = (& $Esptool --chip esp32p4 --port $Port --before $Before --after $After --no-stub @Command 2>&1) -join "`n"
    if ($LASTEXITCODE -eq 0) { return $reply }
    if ($attempt -eq $attempts -or $reply -notmatch 'Could not open port|Could not open COM|FileNotFoundError') {
      throw "ROM command $($Command[0]) failed ($LASTEXITCODE). $reply"
    }
    Start-Sleep -Milliseconds 750
  }
}

# These settings are specific to this assembled board and its trim values.
$identity = Invoke-Rom -Command @('read-mac') -Before 'usb-reset'
if ($identity -notmatch 'e8:f6:0a:ed:68:52' -or $identity -notmatch 'revision v3\.2') {
  throw 'The connected board does not match the verified c26102103 assembly.'
}
$trim = Invoke-Rom -Command @('read-mem', '0x5012d050')
if ($trim -notmatch '0x5012d050 = 0x2c7282e2') { throw 'Unexpected LDO calibration word.' }

# U1.74 supplies U7 and VDD_FLASHIO. Select the 3.3 V input rail, enable
# ripple suppression, then enable channel 4, following ESP-IDF ldo_ll.h.
$null = Invoke-Rom -Command @('write-mem', '0x501151d8', '0x4080', '0x4e80')
$null = Invoke-Rom -Command @('write-mem', '0x501151dc', '0x04000000', '0x04000000')
$null = Invoke-Rom -Command @('write-mem', '0x501151d8', '0x100', '0x100')
$flash = Invoke-Rom -Command @('flash-id')
if ($flash -notmatch 'Manufacturer: ef' -or $flash -notmatch 'Device: 4017' -or $flash -notmatch 'Detected flash size: 8MB') {
  throw 'The expected Winbond W25Q64JV did not respond.'
}
Write-Output 'Winbond EF 40 17, 8 MiB.'
if ($VerifyBuild) {
  $build = (Resolve-Path -LiteralPath $VerifyBuild).Path
  $check = Invoke-Rom -Command @('verify-flash', '0x2000', "$build/HexWallet.ino.bootloader.bin",
      '0x8000', "$build/HexWallet.ino.partitions.bin", '0xe000', "$build/boot_app0.bin", '0x10000', "$build/HexWallet.ino.bin")
  Write-Output $check
}

# U1.73 supplies the PSRAM on this PCB. For its K/Vos/C fields 11/10/7,
# ldo_ll_voltage_to_dref_mul(unit=2, voltage_mv=1800) returns dref=6, mul=5.
# Select the adjustable output (TIEH=0), rather than the 3.3 V rail.
$null = Invoke-Rom -Command @('write-mem', '0x501151c0', '0x80', '0x4e80')
$null = Invoke-Rom -Command @('write-mem', '0x501151c4', '0x66800000', '0xf7800000')
$null = Invoke-Rom -Command @('write-mem', '0x501151c0', '0x100', '0x100')
# A USB reset clears the temporary rail settings. Keep the ROM connected when
# preparing a flash write; the next esptool command must use --before no-reset.
$finalReset = if ($StayInBootloader) { 'no-reset' } else { 'hard-reset' }
Write-Output (Invoke-Rom -Command @('read-mem', '0x501151c0') -After $finalReset)
