param([Parameter(Mandatory)][string]$Port, [switch]$SecureElementOnly)
$ErrorActionPreference = 'Stop'
$serial = [IO.Ports.SerialPort]::new($Port, 115200)
try {
  $serial.WriteTimeout = 500
  $serial.Open()
  $deadline = [DateTime]::UtcNow.AddSeconds(6)
  $answer = ''
  do {
    if ($SecureElementOnly) { $serial.Write('s') } else { $serial.Write('?') }
    Start-Sleep -Milliseconds 300
    $answer += $serial.ReadExisting()
    $start = $answer.IndexOf("HEXWALLET RAM PROBE`r`n")
    $end = $answer.IndexOf("END RAM PROBE`r`n")
    if ($start -ge 0 -and $end -gt $start) {
      Write-Output $answer.Substring($start, $end - $start + 13)
      return
    }
    if ($answer.Length -gt 4096) { throw 'Unexpected data on the probe port' }
  } while ([DateTime]::UtcNow -lt $deadline)
  throw "No complete SRAM probe report on $Port"
} finally {
  $serial.Dispose()
}
