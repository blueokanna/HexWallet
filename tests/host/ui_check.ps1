$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$lvgl = if ($env:HEXWALLET_LVGL_DIR) { $env:HEXWALLET_LVGL_DIR } else { Join-Path $PSScriptRoot 'lvgl_real' }
& powershell -ExecutionPolicy Bypass -File (Join-Path $root 'tools/prepare_lvgl.ps1') -Directory $lvgl
if ($LASTEXITCODE -ne 0) { throw 'LVGL dependency preparation failed' }
$out = Join-Path $root 'build/ui-test'
$arguments = @('-S', (Join-Path $PSScriptRoot 'ui'), '-B', $out, '-A', 'x64')
if ($env:HEXWALLET_LVGL_DIR) { $arguments += "-DLVGL_SOURCE_DIR=$env:HEXWALLET_LVGL_DIR" }
& cmake @arguments
if ($LASTEXITCODE -ne 0) { throw 'UI test configure failed' }
& cmake --build $out --config Release --parallel 4 --target ui_test board_p4_eink_test board_s3_display_test
if ($LASTEXITCODE -ne 0) { throw 'UI test build failed' }
& ctest --test-dir $out -C Release --output-on-failure
if ($LASTEXITCODE -ne 0) { throw 'UI or board runtime regression failed' }
