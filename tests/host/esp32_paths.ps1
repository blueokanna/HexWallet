# Resolves the ESP32 Arduino core / esp32-libs paths used by every host-side
# build. HEXWALLET_ESP32_LIBS may point either at the esp32-libs root or at its
# include\mbedtls directory (CI uses the latter); both forms are accepted.
$coreVersion = if ($env:ESP32_CORE_VERSION) { $env:ESP32_CORE_VERSION } else { "3.3.10" }
$candidate = $env:HEXWALLET_ESP32_LIBS
if (-not $candidate) {
  $candidate = Join-Path $env:LOCALAPPDATA "Arduino15\packages\esp32\tools\esp32-libs\$coreVersion\include\mbedtls"
}

if (Test-Path (Join-Path $candidate "mbedtls\include")) {
  $mbedtlsRoot = $candidate
} elseif (Test-Path (Join-Path $candidate "include\mbedtls\mbedtls\include")) {
  $mbedtlsRoot = Join-Path $candidate "include\mbedtls"
} else {
  throw "ESP32 mbedtls headers not found under '$candidate'. Install esp32:esp32@$coreVersion or set HEXWALLET_ESP32_LIBS to the esp32-libs root (or its include\mbedtls directory)."
}

$espLibsRoot = Split-Path (Split-Path $mbedtlsRoot -Parent) -Parent
$mbedtlsInclude = Join-Path $mbedtlsRoot "mbedtls\include"
$mbedtlsPort = Join-Path $mbedtlsRoot "port\include"

$coreCandidate = $env:HEXWALLET_ESP32_CORE
if (-not $coreCandidate) {
  $coreCandidate = Join-Path $env:LOCALAPPDATA "Arduino15\packages\esp32\hardware\esp32\$coreVersion"
}
if (-not (Test-Path $coreCandidate)) {
  throw "ESP32 Arduino core not found at '$coreCandidate'."
}
