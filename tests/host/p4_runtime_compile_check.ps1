# Compile the orchestration code against real P4 Arduino/FreeRTOS headers.
# This is a compile check, not a firmware link or physical-device test.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'esp32_paths.ps1')
$root=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$toolsRoot=Split-Path (Split-Path $espLibsRoot -Parent) -Parent
$sdk=Join-Path $toolsRoot "esp32p4-libs/$coreVersion"
$compiler=Get-ChildItem (Join-Path $toolsRoot 'esp-rv32') -Recurse -Filter riscv32-esp-elf-g++.exe | Select-Object -First 1 -ExpandProperty FullName
if(!$compiler -or !(Test-Path $sdk)){throw 'Installed ESP32-P4 SDK/toolchain required'}
$out=Join-Path $root 'build/p4-runtime'
New-Item -ItemType Directory -Force $out | Out-Null
$flags=@("@$sdk/flags/cpp_flags","@$sdk/flags/defines",'-iprefix',"$sdk/include/","@$sdk/flags/includes",
  "-I$sdk/dio_qspi/include","-I$coreCandidate/cores/esp32","-I$coreCandidate/variants/esp32p4","-I$root",
  "-I$coreCandidate/libraries/Preferences/src",
  '-DARDUINO=10819','-DARDUINO_ARCH_ESP32','-DHEXWALLET_ENABLE_LVGL=0',
  '-DARDUINO_USB_CDC_ON_BOOT=0','-DARDUINO_USB_MODE=0','-DMBEDTLS_ALLOW_PRIVATE_ACCESS')
foreach($name in @('WalletWorker.cpp','WalletWorkerExecution.cpp','WalletSigning.cpp','WalletLinkService.cpp','WalletCli.cpp','Totp.cpp','HexWallet.ino')) {
  & $compiler @flags -x c++ -include Arduino.h -c (Join-Path $root $name) -o (Join-Path $out "$name.o")
  if($global:LASTEXITCODE -ne 0){throw "P4 runtime compilation failed: $name"}
  Write-Host "${name}: compiled against real P4 headers"
}
