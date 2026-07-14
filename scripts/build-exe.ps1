<#
.SYNOPSIS
  Build a standalone NetScope.exe with PyInstaller.
.DESCRIPTION
  Installs PyInstaller into the project venv (if needed) and builds a one-file
  executable from netscope.spec. Output: dist\netscope.exe. Users then just run
  netscope.exe - no Python install required. (Npcap/Nmap remain optional external
  installs for full capability.)
#>
[CmdletBinding()]
param([switch]$Clean)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) { $Python = "python" }

Write-Host "[*] Ensuring PyInstaller is installed..." -ForegroundColor Cyan
& $Python -m pip install --quiet pyinstaller

if ($Clean) {
  Remove-Item -Recurse -Force (Join-Path $ProjectRoot "build"), (Join-Path $ProjectRoot "dist") -ErrorAction SilentlyContinue
}

Write-Host "[*] Building netscope.exe (this takes a few minutes)..." -ForegroundColor Cyan
Push-Location $ProjectRoot
try {
  & $Python -m PyInstaller --noconfirm netscope.spec
} finally {
  Pop-Location
}

$exe = Join-Path $ProjectRoot "dist\netscope.exe"
if (Test-Path $exe) {
  Write-Host "[+] Built: $exe" -ForegroundColor Green
  Write-Host "    Run it, then open http://127.0.0.1:8000" -ForegroundColor Gray
} else {
  Write-Host "[x] Build failed - see PyInstaller output above." -ForegroundColor Red
}
