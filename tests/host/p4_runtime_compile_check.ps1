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
foreach($name in @('WalletWorker.cpp','WalletWorkerExecution.cpp','WalletSigning.cpp','WalletLinkService.cpp','WalletCli.cpp','WalletMiningCatalog.cpp','WalletTokens.cpp','WalletCustomTokens.cpp','WalletCustomTokensNvs.cpp','Totp.cpp','TotpAccounts.cpp','WalletTotp.cpp','CtapHid.cpp','EinkPanel.cpp','WalletNfcApdu.cpp','HexWallet.ino')) {
  & $compiler @flags -x c++ -include Arduino.h -c (Join-Path $root $name) -o (Join-Path $out "$name.o")
  if($global:LASTEXITCODE -ne 0){throw "P4 runtime compilation failed: $name"}
  Write-Host "${name}: compiled against real P4 headers"
}

# Compile the disabled CLI branch too: it must not reference transport globals.
& $compiler @flags -DHEXWALLET_ENABLE_CLI=0 -x c++ -include Arduino.h -c (Join-Path $root 'WalletCli.cpp') -o (Join-Path $out 'WalletCli-disabled.o')
if($LASTEXITCODE -ne 0){throw 'P4 disabled CLI compilation failed'}

# The actual P4 display port, both panel protocols, and the real LVGL API.
$lv=Join-Path $PSScriptRoot 'lvgl_real/src'
if(!(Test-Path "$lv/lvgl.h")){throw 'LVGL checkout required for P4 display compilation'}
$displayFlags=@($flags | Where-Object { $_ -ne '-DHEXWALLET_ENABLE_LVGL=0' })
$displayFlags+=@('-DHEXWALLET_ENABLE_LVGL=1','-DHEXWALLET_BOARD=7','-DLV_CONF_INCLUDE_SIMPLE',"-I$lv",
  "-I$coreCandidate/libraries/SPI/src","-I$coreCandidate/libraries/Wire/src")
foreach($profile in @(0,1,2)) {
  # A 4-color board must supply its own register table; pass one here so the
  # board-side wiring of HEXWALLET_EPD_COLOR_INIT is actually compiled.
  $profileArgs = @("-DHEXWALLET_EPD_PROFILE=$profile")
  if ($profile -eq 1) {
    $profileArgs += '-DHEXWALLET_EPD_COLOR_INIT={{0x18,1,{0x80}},{0x21,1,{0x00}}}'
  }
  & $compiler @displayFlags @profileArgs -x c++ -include Arduino.h -c (Join-Path $root 'WalletBoardPort.cpp') -o (Join-Path $out "WalletBoardPort-$profile.o")
  if($LASTEXITCODE -ne 0){throw "P4 display profile $profile failed"}
  Write-Host "P4 display profile $profile compiled"
}
& $compiler @displayFlags -x c++ -include Arduino.h -c (Join-Path $root 'WalletUi.cpp') -o (Join-Path $out 'WalletUi.o')
if($LASTEXITCODE -ne 0){throw 'P4 LVGL UI compilation failed'}
