# Compile the actual panel driver and LVGL integration with real S3 headers.
# Missing dependencies are errors, never an implicitly disabled driver branch.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'esp32_paths.ps1')
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$toolsRoot = Split-Path (Split-Path $espLibsRoot -Parent) -Parent
$sdk = Join-Path $toolsRoot "esp32s3-libs/$coreVersion"
$compiler = Get-ChildItem (Join-Path $toolsRoot 'esp-x32') -Recurse -Filter xtensa-esp32s3-elf-g++.exe | Select-Object -First 1 -ExpandProperty FullName
$gx = if ($env:HEXWALLET_GXEPD2_DIR) { $env:HEXWALLET_GXEPD2_DIR } else { Join-Path $root 'build/epd-deps/GxEPD2' }
$lv = if ($env:HEXWALLET_LVGL_DIR) { $env:HEXWALLET_LVGL_DIR } else { Join-Path $PSScriptRoot 'lvgl_real' }
foreach ($required in @($compiler, "$gx/src/GxEPD2_EPD.h", "$lv/src/lvgl.h", "$sdk/flags/cpp_flags")) {
  if (!$required -or !(Test-Path $required)) { throw "Missing EPD compile dependency: $required" }
}
$out = Join-Path $root 'build/epd-driver-compile'
New-Item -ItemType Directory -Force $out | Out-Null
$flags = @("@$sdk/flags/cpp_flags", "@$sdk/flags/defines", '-iprefix', "$sdk/include/", "@$sdk/flags/includes",
  "-I$sdk/qio_qspi/include", "-I$coreCandidate/cores/esp32", "-I$coreCandidate/variants/esp32s3", "-I$root",
  "-I$coreCandidate/libraries/SPI/src", "-I$coreCandidate/libraries/Wire/src", "-I$gx/src", "-I$lv/src",
  '-DARDUINO=10819', '-DARDUINO_ARCH_ESP32', '-DESP32', '-DARDUINO_USB_CDC_ON_BOOT=0', '-DARDUINO_USB_MODE=0',
  '-DLV_CONF_INCLUDE_SIMPLE', '-DHEXWALLET_BOARD=4', '-DHEXWALLET_REQUIRE_EPD_DRIVER=1')
foreach ($source in @("$root/WalletBoardPort.cpp", "$root/WalletUi.cpp", "$root/EinkFrame.cpp",
                      "$gx/src/GxEPD2_EPD.cpp", "$gx/src/gdeq/GxEPD2_310_GDEQ031T10.cpp")) {
  & $compiler @flags -c $source -o (Join-Path $out ((Split-Path $source -Leaf) + '.o'))
  if ($LASTEXITCODE -ne 0) { throw "Actual EPD compilation failed: $source" }
  Write-Output "Compiled against actual EPD/S3/LVGL headers: $(Split-Path $source -Leaf)"
}
