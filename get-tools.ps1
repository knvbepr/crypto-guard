param(
  [string]$ToolsDir = (Join-Path $PSScriptRoot '_tools')
)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Measure-SpeedMB($url) {
  $r = curl.exe -sL --max-time 20 -r 0-2097151 -o NUL -w "%{speed_download}|%{http_code}" $url 2>$null
  if (-not $r) { return -1 }
  $p = $r.Split('|')
  if ($p.Count -lt 2 -or $p[1] -notin @('200','206')) { return -1 }
  return [double]$p[0] / 1MB
}

function Get-Fastest($candidates) {
  $best = $null; $bestSpeed = -1
  foreach ($c in $candidates) {
    $s = Measure-SpeedMB $c.url
    $tag = if ($s -ge 0) { "{0:N2} MB/s" -f $s } else { "unreachable" }
    Write-Host ("  [{0}] {1}" -f $tag, $c.url)
    if ($s -gt $bestSpeed) { $bestSpeed = $s; $best = $c }
  }
  if (-not $best -or $bestSpeed -lt 0) { throw "No reachable mirror for this artifact" }
  Write-Host ("  -> selected {0} ({1:N2} MB/s)" -f $best.url, $bestSpeed) -ForegroundColor Green
  return $best
}

function Download-Artifact($name, $candidates, $outFile) {
  Write-Host "=== $name ===" -ForegroundColor Cyan
  if (Test-Path $outFile) {
    $len = (Get-Item $outFile).Length
    if ($len -gt 100KB) { Write-Host "  already exists ($([math]::Round($len/1MB,1)) MB), skip"; return }
  }
  $best = Get-Fastest $candidates
  curl.exe -L --retry 5 --retry-delay 2 -C - --progress-bar -o $outFile $best.url
  if ($LASTEXITCODE -ne 0) { throw "download failed: $($best.url)" }
  $len = (Get-Item $outFile).Length
  Write-Host ("  downloaded {0} MB" -f [math]::Round($len/1MB,1)) -ForegroundColor Green
}

function Extract-Zip($zip, $dest) {
  if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
  New-Item -ItemType Directory -Path $dest | Out-Null
  tar.exe -xf $zip -C $dest
  if ($LASTEXITCODE -ne 0) { Expand-Archive -Path $zip -DestinationPath $dest -Force }
}

$dl = Join-Path $ToolsDir 'downloads'
New-Item -ItemType Directory -Force -Path $dl | Out-Null

Download-Artifact 'TinyCC (win64)' @(
  @{ url = 'https://download.savannah.gnu.org/releases/tinycc/tcc-0.9.27-win64-bin.zip' }
) "$dl\tcc.zip"
Extract-Zip "$dl\tcc.zip" "$ToolsDir\tcc"

Download-Artifact 'Microsoft OpenJDK 17' @(
  @{ url = 'https://aka.ms/download-jdk/microsoft-jdk-17-windows-x64.zip' },
  @{ url = 'https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.13%2B11/OpenJDK17U-jdk_x64_windows_hotspot_17.0.13_11.zip' }
) "$dl\jdk17.zip"
Extract-Zip "$dl\jdk17.zip" "$ToolsDir\jdk"

Download-Artifact 'Android build-tools r34' @(
  @{ url = 'https://dl.google.com/android/repository/build-tools_r34-windows.zip' },
  @{ url = 'https://dl.google.com/android/repository/build-tools_r33.0.2-windows.zip' }
) "$dl\build-tools.zip"
Extract-Zip "$dl\build-tools.zip" "$ToolsDir\build-tools"

Download-Artifact 'Android platform (android.jar)' @(
  @{ url = 'https://dl.google.com/android/repository/platform-32_r01.zip' },
  @{ url = 'https://dl.google.com/android/repository/platform-35_r02.zip' }
) "$dl\platform.zip"
Extract-Zip "$dl\platform.zip" "$ToolsDir\platform"

Write-Host "`n=== Locate tools ===" -ForegroundColor Cyan
$tcc = Get-ChildItem -Recurse -Filter tcc.exe "$ToolsDir\tcc" | Select-Object -First 1
$javac = Get-ChildItem -Recurse -Filter javac.exe "$ToolsDir\jdk" | Select-Object -First 1
$aapt2 = Get-ChildItem -Recurse -Filter aapt2.exe "$ToolsDir\build-tools" | Select-Object -First 1
$d8 = Get-ChildItem -Recurse -Filter d8.bat "$ToolsDir\build-tools" | Select-Object -First 1
$apksigner = Get-ChildItem -Recurse -Filter apksigner.bat "$ToolsDir\build-tools" | Select-Object -First 1
$zipalign = Get-ChildItem -Recurse -Filter zipalign.exe "$ToolsDir\build-tools" | Select-Object -First 1
$androidJar = Get-ChildItem -Recurse -Filter android.jar "$ToolsDir\platform" | Select-Object -First 1
@{
  tcc = $tcc.FullName; javac = $javac.FullName; aapt2 = $aapt2.FullName; d8 = $d8.FullName;
  apksigner = $apksigner.FullName; zipalign = $zipalign.FullName; androidJar = $androidJar.FullName
} | ConvertTo-Json | Set-Content -Encoding UTF8 "$ToolsDir\tools.json"
Write-Host (Get-Content -Raw "$ToolsDir\tools.json")
Write-Host "ALL TOOLS READY" -ForegroundColor Green
