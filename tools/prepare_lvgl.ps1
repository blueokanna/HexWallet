# Apply the reviewed callback ABI fix to the pinned LVGL 9.5.0 source.
# SHA-256 is checked before and after editing; unknown source is never changed.
param([Parameter(Mandatory = $true)][string]$Directory)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $Directory).Path
$version = [IO.File]::ReadAllText((Join-Path $root 'lv_version.h'))
foreach ($part in @(@('MAJOR', 9), @('MINOR', 5), @('PATCH', 0))) {
  if ($version -notmatch "(?m)^#define LVGL_VERSION_$($part[0]) $($part[1])\s*$") {
    throw 'This integration patch requires LVGL 9.5.0.'
  }
}
$path = Join-Path $root 'src/draw/sw/lv_draw_sw_mask.c'
$source = [IO.File]::ReadAllText($path).Replace("`r`n", "`n")
function Text-Hash([string]$Text) {
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))).Replace('-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
}
$original = 'e1f852a16219644ae2d8a08c8bb49865a6f5af1bb3e2115ec3e423de46675c22'
$patched = '5a4827156b8f77655089515c6bbe51a2044f949bb1cee47523f99c3174031996'
$actual = Text-Hash $source
if ($actual -eq $patched) { Write-Output 'LVGL 9.5.0 callback ABI patch already verified'; exit 0 }
if ($actual -ne $original) { throw 'Unrecognized LVGL mask source; refusing to overwrite local changes.' }
foreach ($kind in @('line', 'angle', 'radius', 'fade', 'map')) {
  $type = "lv_draw_sw_mask_${kind}_param_t"
  $prototype = "(?s)(static lv_draw_sw_mask_res_t /\* LV_ATTRIBUTE_FAST_MEM \*/ lv_draw_mask_$kind\([^;{}]*?)$type \* param\);"
  $definition = "(?s)(static lv_draw_sw_mask_res_t LV_ATTRIBUTE_FAST_MEM lv_draw_mask_$kind\([^;{}]*?)$type \* p\)`n\{"
  if ([regex]::Matches($source, $prototype).Count -ne 1 -or [regex]::Matches($source, $definition).Count -ne 1) {
    throw "Unexpected callback declaration or definition: $kind"
  }
  $source = [regex]::Replace($source, $prototype, '${1}void * param);')
  $source = [regex]::Replace($source, $definition, ('${1}void * opaque)' + "`n{`n    $type * p = opaque;"))
  $source = $source.Replace("(lv_draw_sw_mask_xcb_t)lv_draw_mask_$kind", "lv_draw_mask_$kind")
}
if ((Text-Hash $source) -ne $patched) { throw 'LVGL patch result differs from the reviewed source.' }
$temporary = "$path.$([Guid]::NewGuid().ToString('N')).tmp"
try {
  [IO.File]::WriteAllText($temporary, $source, (New-Object Text.UTF8Encoding($false)))
  Move-Item -LiteralPath $temporary -Destination $path -Force
} finally {
  if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
}
Write-Output 'LVGL 9.5.0 callback ABI patch applied and verified'
