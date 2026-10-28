$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$fixtures = Join-Path $root 'tests/fixtures/monero-bp-plus'
$exe = Join-Path $root 'build/monero-reference/monero_reference.exe'
& (Join-Path $PSScriptRoot 'fetch_reference.ps1')
$original = @(Get-Content (Join-Path $fixtures 'outputs-1.txt'))
$data = Get-Content (Join-Path $fixtures 'outputs-1.json') -Raw | ConvertFrom-Json
$generators = Get-Content (Join-Path $fixtures 'generators.json') -Raw | ConvertFrom-Json
$cases = @()
$fields = @('V','A','A1','B','r1','s1','d1')
for($i=0;$i -lt 6;$i++){ $fields+="L_$i" }
for($i=0;$i -lt 6;$i++){ $fields+="R_$i" }
for($i=0;$i -lt $fields.Count;$i++) {
  $value = $generators.generator_0
  if($fields[$i] -in @('r1','s1','d1')) {
    $value = '0100000000000000000000000000000000000000000000000000000000000000'
  }
  $cases += @{name="replace-$($fields[$i])";line=$i+1;replacement=$value;expected='reject';source='outputs-1; replace named proof field with canonical scalar/point'}
}
$cases += @{name='noncanonical-scalar';line=5;replacement=('ff'*32);expected='reject';source='outputs-1; r1 exceeds scalar order'}
$cases += @{name='illegal-point';line=2;replacement=('ff'*32);expected='reject';source='outputs-1; invalid A encoding'}
$cases += @{name='negative-zero-point';line=2;replacement=('01'+('00'*30)+'80');expected='reject';source='outputs-1; A has x=0 with sign bit set'}
foreach($n in @(0,1,2,7,19)) { $cases+=@{name="truncate-$n";truncate_lines=$n;expected='reject';source='outputs-1; truncate key records'} }
$candidate=Join-Path $root 'build/monero-reference/negative.txt'
foreach($case in $cases) {
  $lines=@($original)
  if($case.ContainsKey('truncate_lines')) { $lines=@($lines | Select-Object -First $case.truncate_lines) }
  else { $lines[$case.line]=$case.replacement }
  [IO.File]::WriteAllText($candidate,($lines -join "`n")+"`n",[Text.UTF8Encoding]::new($false))
  # Native stderr describes malformed encodings; the exit status is authoritative.
  $process = Start-Process -FilePath $exe -ArgumentList @('--read',"`"$candidate`"") -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput "$candidate.out" -RedirectStandardError "$candidate.err"
  if($process.ExitCode -notin @(1,2)) { throw "Unexpected upstream result: $($case.name) -> $($process.ExitCode)" }
  $case.reference_returncode=$process.ExitCode
}
[IO.File]::WriteAllText((Join-Path $fixtures 'negative-cases.json'),($cases | ConvertTo-Json -Depth 4)+"`n",[Text.UTF8Encoding]::new($false))
Write-Host "$($cases.Count) invalid cases rejected independently."
