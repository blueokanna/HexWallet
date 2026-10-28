param(
  [string]$SdkPath = 'build/nxp-plug-and-trust',
  [switch]$Device
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location $root
try {
  $sdkPath = [IO.Path]::GetFullPath((Join-Path $root $SdkPath))
  $revision = & git -C $sdkPath rev-parse HEAD
  if ($LASTEXITCODE -ne 0 -or $revision -ne '7102413e0457d3dfa4fc4be686ca8ec50bd9f5e2') {
    throw 'Expected NXP/plug-and-trust commit 7102413e0457d3dfa4fc4be686ca8ec50bd9f5e2'
  }
  if (& git -C $sdkPath status --porcelain --untracked-files=no) {
    throw 'NXP checkout has local modifications; refusing ABI verification'
  }
  $portInclude = Join-Path $sdkPath 'hostlib/hostLib/platform/inc'
  $infraInclude = Join-Path $sdkPath 'hostlib/hostLib/libCommon/infra'
  $out = Join-Path $root 'build/se051-check'
  New-Item -ItemType Directory -Force $out | Out-Null
  if ($Device) {
    . (Join-Path $PSScriptRoot 'esp32_paths.ps1')
    $toolsRoot = Split-Path (Split-Path $espLibsRoot -Parent) -Parent
    $p4 = Join-Path $toolsRoot "esp32p4-libs/$coreVersion"
    $cc = Get-ChildItem (Join-Path $toolsRoot 'esp-rv32') -Recurse -Filter riscv32-esp-elf-g++.exe |
      Select-Object -First 1 -ExpandProperty FullName
    if (!$cc -or !(Test-Path $p4)) { throw 'ESP32-P4 toolchain required' }
    $flags = @("@$p4/flags/cpp_flags", "@$p4/flags/defines", '-iprefix', "$p4/include/",
      "@$p4/flags/includes", "-I$p4/dio_qspi/include", "-I$coreCandidate/cores/esp32",
      "-I$coreCandidate/variants/esp32p4", "-I$coreCandidate/libraries/Wire/src", "-I$root",
      "-I$portInclude", "-I$infraInclude", '-DARDUINO=10819', '-DARDUINO_ARCH_ESP32',
      '-DHEXWALLET_ENABLE_LVGL=0', '-DHEXWALLET_BOARD=7', '-DT1oI2C', '-DHEXWALLET_ENABLE_NXP_SE051=1')
    & $cc @flags -c Se051ArduinoPort.cpp -o (Join-Path $out 'p4-port.o')
    if ($LASTEXITCODE -ne 0) { throw 'P4 port compilation failed' }
    Write-Output 'se051-p4-port-compile=pass (compile only; no hardware test)'
  } else {
    $vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
    $vsInstall = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (!$vsInstall) { throw 'MSVC C++ toolchain required' }
    $vcvars = Join-Path $vsInstall 'VC/Auxiliary/Build/vcvars64.bat'
    cmd /c "`"$vcvars`" >nul 2>&1 && set" | ForEach-Object {
      if ($_ -match '^([^=]+)=(.*)$') { Set-Item -Path "env:$($matches[1])" -Value $matches[2] }
    }
    & cl /nologo /std:c++17 /EHsc /W4 /WX /Itests/host/se051_mock /I. "/I$portInclude" "/I$infraInclude" `
      /DHEXWALLET_ENABLE_NXP_SE051=1 /DHEXWALLET_SE051_PORT_TEST=1 /DHEXWALLET_BOARD=7 `
      /DHEXWALLET_ENABLE_LVGL=0 /DT1oI2C Se051ArduinoPort.cpp tests/host/se051_port_test.cpp `
      "/Fo$out/" "/Fe$out/se051_port_test.exe"
    if ($LASTEXITCODE -ne 0) { throw 'Host port compilation failed' }
    & (Join-Path $out 'se051_port_test.exe')
    if ($LASTEXITCODE -ne 0) { throw 'SE051 port fault tests failed' }
  }
} finally { Pop-Location }
