<#
.SYNOPSIS
  One-command setup for deep packet inspection with Suricata and Zeek, wired
  into NetScope. Installs the engines, points NetScope at their logs, and (for
  Suricata) can start live monitoring.

.DESCRIPTION
  Suricata runs natively on Windows using Npcap and does live intrusion
  detection on the selected network adapter, writing alerts to eve.json.
  Zeek has no native Windows build, so it runs via Docker to analyze captured
  traffic (PCAP files) into connection/notice logs. Both log locations are
  written to NetScope's .env so the Security tab picks them up automatically.

.PARAMETER Tool
  Which engine(s) to set up: all (default), suricata, or zeek.

.PARAMETER Start
  After setup, start Suricata live monitoring (requires Administrator).

.PARAMETER Pcap
  A .pcap/.pcapng file for Zeek to analyze immediately.

.EXAMPLE
  # Set up both engines and point NetScope at them
  powershell -ExecutionPolicy Bypass -File scripts\setup-ids.ps1

.EXAMPLE
  # Set up Suricata and start live monitoring (run as Administrator)
  powershell -ExecutionPolicy Bypass -File scripts\setup-ids.ps1 -Tool suricata -Start

.NOTES
  For Suricata/Zeek to see OTHER devices' traffic (not just this PC's), the
  engine must run where it can observe that traffic: on your router, on a PC
  attached to a switch mirror/SPAN port, or against a PCAP captured there.
  On this PC alone, it inspects this PC's own traffic - still useful for
  catching malware your machine talks to.
#>
[CmdletBinding()]
param(
  [ValidateSet("all", "suricata", "zeek")]
  [string]$Tool = "all",
  [switch]$Start,
  [string]$Pcap = ""
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) { $Python = "python" }

function Info($m)  { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)    { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m)  { Write-Host "[!] $m" -ForegroundColor Yellow }
function Fail($m)  { Write-Host "[x] $m" -ForegroundColor Red }

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Set-NetScopeEnv($key, $value) {
  & $Python -m netscope.envfile "$key=$value" | Out-Null
  Ok "NetScope .env: $key -> $value"
}

# --------------------------------------------------------------------------- #
# Suricata
# --------------------------------------------------------------------------- #
function Setup-Suricata {
  Info "Setting up Suricata (native Windows IDS)..."

  $suricataExe = "C:\Program Files\Suricata\suricata.exe"
  if (-not (Test-Path $suricataExe)) {
    Info "Installing Suricata via winget (OISF.Suricata)..."
    winget install --id OISF.Suricata --accept-package-agreements --accept-source-agreements --disable-interactivity
  } else {
    Ok "Suricata already installed."
  }
  if (-not (Test-Path $suricataExe)) {
    Fail "Suricata install not found at $suricataExe. Aborting Suricata setup."
    return
  }

  $installDir = Split-Path $suricataExe
  $logDir = Join-Path $installDir "log"
  New-Item -ItemType Directory -Force -Path $logDir | Out-Null
  $evePath = Join-Path $logDir "eve.json"

  # Fetch/refresh the Emerging Threats Open ruleset (best effort).
  Info "Updating rules (suricata-update)..."
  try {
    $updater = Get-Command suricata-update -ErrorAction SilentlyContinue
    if (-not $updater) {
      & $Python -m pip install --quiet suricata-update
    }
    & $Python -m suricata.update --suricata "$suricataExe" `
      --suricata-conf "$installDir\suricata.yaml" -D "$installDir" 2>&1 | Out-Null
    Ok "Ruleset updated."
  } catch {
    Warn "Rule update skipped ($($_.Exception.Message)). Suricata will use bundled rules; re-run 'suricata-update' later."
  }

  # Detect the active adapter's Npcap device for live capture.
  $device = Get-SuricataInterface $suricataExe
  if ($device) { Ok "Selected capture interface: $device" }
  else { Warn ("Could not auto-detect an interface; run '{0} --list-interfaces' and pass -i manually." -f $suricataExe) }

  Set-NetScopeEnv "NETSCOPE_SURICATA_EVE" $evePath

  $runCmd = '"{0}" -c "{1}" -l "{2}"' -f $suricataExe, "$installDir\suricata.yaml", $logDir
  if ($device) { $runCmd += " -i $device" }

  if ($Start) {
    if (-not (Test-Admin)) {
      Warn "Live capture needs Administrator. Re-run this script as Administrator with -Start, or run manually:"
      Write-Host "    $runCmd" -ForegroundColor Gray
    } else {
      Info "Starting Suricata live monitoring in a new window..."
      Start-Process -FilePath $suricataExe `
        -ArgumentList @("-c", "$installDir\suricata.yaml", "-l", "$logDir", "-i", "$device")
      Ok "Suricata started. Alerts will stream into NetScope's Security tab."
    }
  } else {
    Info "To start live monitoring (as Administrator):"
    Write-Host "    $runCmd" -ForegroundColor Gray
  }
}

function Get-SuricataInterface($suricataExe) {
  try {
    $guid = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
      Sort-Object RouteMetric | Select-Object -First 1 |
      Get-NetAdapter -ErrorAction SilentlyContinue).InterfaceGuid
    if ($guid) { return "\Device\NPF_$guid" }
  } catch {}
  return $null
}

# --------------------------------------------------------------------------- #
# Zeek (via Docker)
# --------------------------------------------------------------------------- #
function Setup-Zeek {
  Info "Setting up Zeek (via Docker)..."

  $docker = Get-Command docker -ErrorAction SilentlyContinue
  if (-not $docker) {
    Fail "Docker not found. Install Docker Desktop, then re-run. (Zeek has no native Windows build.)"
    return
  }

  Info "Pulling zeek/zeek image (first run only, ~hundreds of MB)..."
  docker pull zeek/zeek:latest

  $zeekLogs = Join-Path $ProjectRoot "zeek-logs"
  New-Item -ItemType Directory -Force -Path $zeekLogs | Out-Null
  Set-NetScopeEnv "NETSCOPE_ZEEK_DIR" $zeekLogs

  if ($Pcap) {
    if (-not (Test-Path $Pcap)) { Fail "PCAP not found: $Pcap"; return }
    & (Join-Path $PSScriptRoot "zeek-process-pcap.ps1") -Pcap $Pcap -OutDir $zeekLogs
  } else {
    Ok "Zeek ready. Analyze a capture file with:"
    Write-Host "    powershell -File scripts\zeek-process-pcap.ps1 -Pcap C:\path\to\capture.pcap" -ForegroundColor Gray
    Info "Tip: capture traffic to a PCAP with Wireshark/dumpcap (ideally from a switch mirror port), then run the line above."
  }
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
Write-Host ""
Info "NetScope IDS setup - tool: $Tool"
Write-Host ""

if ($Tool -in @("all", "suricata")) { Setup-Suricata; Write-Host "" }
if ($Tool -in @("all", "zeek"))     { Setup-Zeek;     Write-Host "" }

Ok "Done. Restart NetScope (python -m netscope) so it reads the new .env, then open the Security tab."
