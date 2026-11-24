param(
  [string]$ArduinoCli = 'arduino-cli',
  [string]$ConfigFile,
  [string]$Lvgl = "$HOME/Arduino/libraries/lvgl",
  [string]$BuildDirectory,
  [ValidateSet(8, 32)][int]$FlashSizeMiB = 32,
  [switch]$UsbSerialJtag
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (!$BuildDirectory) {
  $variant = 'hexwallet-p4-v3'
  if ($FlashSizeMiB -ne 32) { $variant += "-${FlashSizeMiB}mb" }
  if ($UsbSerialJtag) { $variant += '-usb' }
  $BuildDirectory = Join-Path $root "build/$variant"
}
$build = [IO.Path]::GetFullPath($BuildDirectory)
$layoutName = "hexwallet-p4-${FlashSizeMiB}mb.csv"
$layout = Join-Path $root "partitions/$layoutName"
# Arduino CLI can clean the build directory before executing platform hooks.
# Use the first hook to select the layout on every compile, including retries.
$partitionHook = 'recipe.hooks.prebuild.1.pattern=cp "{build.source.path}/partitions/LAYOUT" "{build.path}/partitions.csv"'.Replace('LAYOUT', $layoutName)
$imageFlags = '--chip {build.mcu} elf2image --flash-mode {build.flash_mode} --flash-freq {build.img_freq} --flash-size {build.flash_size} --min-rev-full 301 --max-rev-full 399'
$applicationRecipe = 'recipe.objcopy.bin.pattern_args=' + $imageFlags + ' --elf-sha256-offset 0xb0 -o "{build.path}/{build.project_name}.bin" "{build.path}/{build.project_name}.elf"'
$mergeRecipe = 'recipe.hooks.objcopy.postobjcopy.3.pattern_args=--chip {build.mcu} merge-bin -o "{build.path}/{build.project_name}.merged.bin" --pad-to-size 8MB --flash-mode keep --flash-freq keep --flash-size keep {build.bootloader_addr} "{build.path}/{build.project_name}.bootloader.bin" 0x8000 "{build.path}/{build.project_name}.partitions.bin" 0xe000 "{runtime.platform.path}/tools/partitions/boot_app0.bin" 0x10000 "{build.path}/{build.project_name}.bin"'
if ($env:OS -eq 'Windows_NT') {
  $partitionHook = 'recipe.hooks.prebuild.1.pattern=cmd /c copy /y "{build.source.path}\partitions\LAYOUT" "{build.path}\partitions.csv"'.Replace('LAYOUT', $layoutName)
  if ($PSVersionTable.PSVersion.Major -lt 7) {
    $partitionHook = $partitionHook.Replace('"', '\"')
    $applicationRecipe = $applicationRecipe.Replace('"', '\"')
    $mergeRecipe = $mergeRecipe.Replace('"', '\"')
  }
}
$cliArgs = @()
if ($ConfigFile) { $cliArgs += @('--config-file', $ConfigFile) }
$platforms = & $ArduinoCli @cliArgs core list --json
if ($LASTEXITCODE) { throw 'Cannot identify the installed Arduino-ESP32 platform' }
$esp32 = (($platforms -join "`n" | ConvertFrom-Json).platforms | Where-Object id -eq 'esp32:esp32')
if ($esp32.installed_version -ne '3.3.13') {
  throw "Board 7 requires esp32:esp32@3.3.13. Selected configuration reports '$($esp32.installed_version)'."
}
$fqbn = "esp32:esp32:esp32p4:ChipVariant=postv3,FlashSize=${FlashSizeMiB}M,PartitionScheme=min_spiffs,PSRAM=enabled"
if ($UsbSerialJtag) { $fqbn += ',USBMode=hwcdc,CDCOnBoot=cdc' }
$cliArgs += @('compile', '--fqbn', $fqbn,
  '--jobs', '6', '--build-path', $build, '--library', $Lvgl,
  '--build-property', $partitionHook,
  '--build-property', "recipe.hooks.prebuild.4.pattern_args=$imageFlags -o",
  '--build-property', $applicationRecipe,
  '--build-property', $mergeRecipe,
  '--build-property', 'upload.maximum_size=3932160',
  '--build-property', 'compiler.c.elf.extra_flags=-Wl,--wrap=nvs_flash_init',
  '--build-property', 'compiler.cpp.extra_flags=-DLV_CONF_INCLUDE_SIMPLE -DHEXWALLET_BOARD=7',
  '--build-property', 'compiler.c.extra_flags=-DLV_CONF_INCLUDE_SIMPLE -DHEXWALLET_BOARD=7', $root)
& $ArduinoCli @cliArgs
if ($LASTEXITCODE) { throw "Board 7 compilation failed ($LASTEXITCODE)" }
if ((Get-FileHash $layout).Hash -ne (Get-FileHash (Join-Path $build 'partitions.csv')).Hash) {
  throw 'Arduino selected a different partition table for board 7'
}
$sdkConfig = Get-Content -LiteralPath (Join-Path $build 'sdkconfig')
if ($sdkConfig -notcontains 'CONFIG_ESP32P4_REV_MIN_FULL=301' -or $sdkConfig -notcontains 'CONFIG_ESP32P4_REV_MAX_FULL=399') {
  throw 'Check board 7 image revision bounds against the selected SDK'
}
foreach ($name in 'HexWallet.ino.bootloader.bin', 'HexWallet.ino.bin') {
  $image = [IO.File]::ReadAllBytes((Join-Path $build $name))
  if ($image.Length -lt 24 -or $image[0] -ne 0xe9 -or (1 -shl ($image[3] -shr 4)) -ne $FlashSizeMiB -or [BitConverter]::ToUInt16($image,12) -ne 18 -or
      [BitConverter]::ToUInt16($image,15) -ne 301 -or [BitConverter]::ToUInt16($image,17) -ne 399) {
    throw "Unexpected chip or revision in $name"
  }
}
& python (Join-Path $PSScriptRoot 'check_p4_image.py') $build $FlashSizeMiB
if ($LASTEXITCODE) { throw 'Board 7 factory image validation failed' }
