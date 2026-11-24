param(
  [Parameter(Mandatory)][string]$EspTools,
  [string]$OutputDirectory,
  [switch]$HinkE029A01,
  [switch]$E029A01N16C355,
  [ValidateSet(0, 1)][int]$EpdBusyActiveLevel
)
$ErrorActionPreference = 'Stop'
if ($HinkE029A01 -and $E029A01N16C355) { throw 'Select one e-paper profile.' }
$toolsDir = (Resolve-Path -LiteralPath $EspTools).Path
$sdk = Join-Path $toolsDir 'esp32p4-libs/3.3.13'
$compiler = Join-Path $toolsDir 'esp-rv32/2610/bin/riscv32-esp-elf-g++'
$esptool = Join-Path $toolsDir 'esptool_py/5.3.1/esptool'
$root = (Resolve-Path "$PSScriptRoot/../..").Path
$profileFlags = @()
$variant = 'p4-ram-probe'
if ($HinkE029A01) {
  $profileFlags += '-DHEXWALLET_EPD_PROFILE=3'
  $variant += '-hink'
}
if ($E029A01N16C355) {
  $profileFlags += '-DHEXWALLET_EPD_PROFILE=4'
  $variant += '-n16c355'
}
if ($PSBoundParameters.ContainsKey('EpdBusyActiveLevel')) {
  $profileFlags += "-DHEXWALLET_EPD_BUSY_ACTIVE_LEVEL=$EpdBusyActiveLevel"
  $variant += "-busy$EpdBusyActiveLevel"
}
if (!$OutputDirectory) { $OutputDirectory = Join-Path $root "build/$variant" }
$out = [IO.Directory]::CreateDirectory($OutputDirectory).FullName
$elf = Join-Path $out 'probe.elf'
$bin = Join-Path $out 'probe.bin'
$compileArgs = @(
  '-march=rv32imac_zicsr_zifencei', '-mabi=ilp32', '-std=gnu++17', '-Os', '-ffreestanding',
  '-fno-builtin', '-fno-exceptions', '-fno-rtti', '-fno-stack-protector', '-fno-jump-tables',
  '-msmall-data-limit=0', '-mno-relax', '-nostdlib', '-DHEXWALLET_BOARD=7', '-DHEXWALLET_ENABLE_LVGL=0',
  "-I$root", "-I$sdk/qio_qspi/include", '-iprefix', "$sdk/include/", "@$sdk/flags/includes",
  '-Wl,--no-relax', "-T$PSScriptRoot/probe.ld", "-T$sdk/ld/esp32p4.rom.eco5.ld",
  "-T$sdk/ld/esp32p4.rom.eco5.libc.ld", "-T$sdk/ld/esp32p4.peripherals.ld",
  '-o', $elf, "$PSScriptRoot/probe.cpp"
)
& $compiler @profileFlags @compileArgs
if ($LASTEXITCODE) { throw 'SRAM probe compilation failed' }
& $esptool --chip esp32p4 elf2image --min-rev-full 301 --max-rev-full 399 -o $bin $elf
if ($LASTEXITCODE) { throw 'SRAM probe image generation failed' }
& $esptool --chip esp32p4 image-info $bin
if ($LASTEXITCODE) { throw 'Invalid SRAM probe image' }
