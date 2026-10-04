$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$tcc = Join-Path $root '_tools\tcc\tcc\tcc.exe'

Write-Host '=== generate icons ===' -ForegroundColor Cyan
node (Join-Path $root 'assets\icon-gen.js')

Write-Host '=== build seticon tool ===' -ForegroundColor Cyan
& $tcc -O2 (Join-Path $PSScriptRoot 'seticon.c') -o (Join-Path $root '_tools\seticon.exe')
if ($LASTEXITCODE -ne 0) { throw 'seticon build failed' }

Write-Host '=== build console test ===' -ForegroundColor Cyan
& $tcc -O2 (Join-Path $PSScriptRoot 'guard.c') -DGUARD_TEST -o (Join-Path $root '_tools\guardtest.exe')
if ($LASTEXITCODE -ne 0) { throw 'console build failed' }

Write-Host '=== build GUI ===' -ForegroundColor Cyan
& $tcc -O2 '-Wl,-subsystem,windows' (Join-Path $PSScriptRoot 'guard.c') -lcomdlg32 -lshell32 -o (Join-Path $root '_tools\guardgui.exe')
if ($LASTEXITCODE -ne 0) { throw 'GUI build failed' }

Write-Host '=== inject icon ===' -ForegroundColor Cyan
& (Join-Path $root '_tools\seticon.exe') (Join-Path $PSScriptRoot 'app.ico') (Join-Path $root '_tools\guardgui.exe')
if ($LASTEXITCODE -ne 0) { throw 'icon injection failed' }

$dest = Join-Path $root '加密卫士.exe'
Copy-Item (Join-Path $root '_tools\guardgui.exe') $dest -Force
$size = [math]::Round((Get-Item $dest).Length / 1KB, 1)
Write-Host "EXE ready: $dest ($size KB)" -ForegroundColor Green
