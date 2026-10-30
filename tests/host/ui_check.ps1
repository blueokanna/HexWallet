$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$out = Join-Path $root 'build/ui-test'
$arguments = @('-S', (Join-Path $PSScriptRoot 'ui'), '-B', $out, '-A', 'x64')
if ($env:HEXWALLET_LVGL_DIR) { $arguments += "-DLVGL_SOURCE_DIR=$env:HEXWALLET_LVGL_DIR" }
& cmake @arguments
if ($LASTEXITCODE -ne 0) { throw 'UI test configure failed' }
& cmake --build $out --config Release --parallel 4 --target ui_test
if ($LASTEXITCODE -ne 0) { throw 'UI test build failed' }
& (Join-Path $out 'Release/ui_test.exe')
if ($LASTEXITCODE -ne 0) { throw 'UI regression failed' }
