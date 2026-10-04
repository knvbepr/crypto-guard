$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$tools = Join-Path $root '_tools'

$jdk = (Get-ChildItem (Join-Path $tools 'jdk') -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'bin\javac.exe') } | Select-Object -First 1).FullName
$bt = (Get-ChildItem (Join-Path $tools 'build-tools') -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'aapt2.exe') } | Select-Object -First 1).FullName
$plat = (Get-ChildItem (Join-Path $tools 'platform') -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'android.jar') } | Select-Object -First 1).FullName

$env:JAVA_HOME = $jdk
$env:Path = "$jdk\bin;$env:Path"
$androidJar = Join-Path $plat 'android.jar'
$src = Join-Path $PSScriptRoot 'src'
$out = Join-Path $PSScriptRoot 'out'

Write-Host "JDK: $jdk"
Write-Host "Build-tools: $bt"
Write-Host "android.jar: $androidJar"

if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Force -Path (Join-Path $out 'classes'), (Join-Path $out 'dex') | Out-Null

Write-Host '=== javac ===' -ForegroundColor Cyan
$javaFiles = Get-ChildItem (Join-Path $src 'com\guard\encryptor') -Filter *.java | ForEach-Object { $_.FullName }
& "$jdk\bin\javac.exe" -encoding UTF-8 --release 8 -cp $androidJar -d (Join-Path $out 'classes') $javaFiles
if ($LASTEXITCODE -ne 0) { throw 'javac failed' }

Write-Host '=== d8 ===' -ForegroundColor Cyan
$classFiles = Get-ChildItem (Join-Path $out 'classes') -Recurse -Filter *.class | ForEach-Object { $_.FullName }
& (Join-Path $bt 'd8.bat') --min-api 21 --lib $androidJar --output (Join-Path $out 'dex') $classFiles
if ($LASTEXITCODE -ne 0) { throw 'd8 failed' }

Write-Host '=== icon resources ===' -ForegroundColor Cyan
node (Join-Path $root 'assets\icon-gen.js') | Out-Null
& (Join-Path $bt 'aapt2.exe') compile --dir (Join-Path $PSScriptRoot 'res') -o (Join-Path $out 'res.zip')
if ($LASTEXITCODE -ne 0) { throw 'aapt2 compile failed' }

Write-Host '=== aapt2 link ===' -ForegroundColor Cyan
& (Join-Path $bt 'aapt2.exe') link -o (Join-Path $out 'base.apk') -I $androidJar `
  --manifest (Join-Path $PSScriptRoot 'AndroidManifest.xml') (Join-Path $out 'res.zip') `
  --min-sdk-version 21 --target-sdk-version 32 --version-code 1 --version-name 1.0
if ($LASTEXITCODE -ne 0) { throw 'aapt2 failed' }

Write-Host '=== add classes.dex ===' -ForegroundColor Cyan
& "$jdk\bin\jar.exe" uf (Join-Path $out 'base.apk') -C (Join-Path $out 'dex') classes.dex
if ($LASTEXITCODE -ne 0) { throw 'jar failed' }

Write-Host '=== zipalign ===' -ForegroundColor Cyan
& (Join-Path $bt 'zipalign.exe') -f 4 (Join-Path $out 'base.apk') (Join-Path $out 'aligned.apk')
if ($LASTEXITCODE -ne 0) { throw 'zipalign failed' }

$ks = Join-Path $PSScriptRoot 'debug.keystore'
if (-not (Test-Path $ks)) {
  Write-Host '=== keytool (create debug keystore) ===' -ForegroundColor Cyan
  & "$jdk\bin\keytool.exe" -genkeypair -keystore $ks -alias androiddebugkey `
    -storepass android -keypass android -dname "CN=Android Debug,O=Android,C=US" `
    -keyalg RSA -keysize 2048 -validity 10000
  if ($LASTEXITCODE -ne 0) { throw 'keytool failed' }
}

Write-Host '=== apksigner ===' -ForegroundColor Cyan
& (Join-Path $bt 'apksigner.bat') sign --ks $ks --ks-pass pass:android --key-pass pass:android `
  --ks-key-alias androiddebugkey --out (Join-Path $out 'app-signed.apk') (Join-Path $out 'aligned.apk')
if ($LASTEXITCODE -ne 0) { throw 'apksigner failed' }

& (Join-Path $bt 'apksigner.bat') verify --print-certs (Join-Path $out 'app-signed.apk') | Select-Object -First 4

$dest = Join-Path $root '加密卫士.apk'
Copy-Item (Join-Path $out 'app-signed.apk') $dest -Force
$size = [math]::Round((Get-Item $dest).Length / 1KB, 1)
Write-Host "APK ready: $dest ($size KB)" -ForegroundColor Green
