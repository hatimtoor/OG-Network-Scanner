<#
.SYNOPSIS
  Install / remove Suricata IDS on an OpenWrt router over SSH (works over Wi-Fi),
  and stream its alerts into NetScope. Includes an explicit consent prompt, a
  plain-language explanation of what it does to your router, and a clean
  uninstall.

.DESCRIPTION
  This talks to an OpenWrt router only. It will NOT work on stock ISP routers
  (they don't allow installing software). Suricata runs in DETECTION mode only
  (it watches and alerts; it never blocks your traffic), and logs are written to
  the router's RAM (/tmp) so they don't wear out its flash storage.

.PARAMETER Action
  install (default) | uninstall | status | sync

.PARAMETER Router
  Router IP / hostname (default 192.168.1.1).

.PARAMETER User
  SSH user (default root).

.PARAMETER Interface
  Router interface to monitor (default br-lan = the LAN bridge).

.PARAMETER SyncMinutes
  How often to pull the router's alert log to this PC (default 5).

.PARAMETER Yes
  Skip the interactive confirmation (for unattended use). Use with care.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\setup-router-ids.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\setup-router-ids.ps1 -Action uninstall
#>
[CmdletBinding()]
param(
  [ValidateSet("install", "uninstall", "status", "sync")]
  [string]$Action = "install",
  [string]$Router = "192.168.1.1",
  [string]$User = "root",
  [string]$Interface = "br-lan",
  [int]$SyncMinutes = 5,
  [switch]$Yes
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) { $Python = "python" }
$RouterLogDir = Join-Path $ProjectRoot "router-logs"
$LocalEve = Join-Path $RouterLogDir "eve.json"
$RemoteEve = "/tmp/suricata/eve.json"

function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Fail($m) { Write-Host "[x] $m" -ForegroundColor Red }

function Test-SshClient {
  if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
    Fail "OpenSSH client not found. Install it: Settings > Apps > Optional Features > OpenSSH Client."
    exit 1
  }
}

function Invoke-RouterSSH([string]$script) {
  # Runs a shell script on the router via one SSH session (one password prompt).
  $target = "$User@$Router"
  $script | ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 $target sh 2>&1
}

# --------------------------------------------------------------------------- #
# Consent / effects explanation
# --------------------------------------------------------------------------- #
function Show-Effects {
  Write-Host ""
  Write-Host "  ============================================================" -ForegroundColor Yellow
  Write-Host "   WHAT THIS WILL DO TO YOUR ROUTER ($Router)" -ForegroundColor Yellow
  Write-Host "  ============================================================" -ForegroundColor Yellow
  Write-Host ""
  Write-Host "  This installs the Suricata intrusion-detection engine on your"
  Write-Host "  OpenWrt router and streams its alerts to NetScope."
  Write-Host ""
  Write-Host "  IT WILL:" -ForegroundColor White
  Write-Host "   - Download & install the 'suricata' package via opkg (uses"
  Write-Host "     router storage; the engine + rules can be several MB)."
  Write-Host "   - Watch traffic on interface '$Interface' in DETECTION mode"
  Write-Host "     ONLY. It ALERTS on suspicious traffic; it does NOT block or"
  Write-Host "     drop any of your traffic."
  Write-Host "   - Write alert logs to the router's RAM (/tmp) to avoid wearing"
  Write-Host "     out flash. (Those logs reset when the router reboots.)"
  Write-Host "   - Enable Suricata to start on boot, and start it now."
  Write-Host "   - Create a Windows scheduled task that copies the alert log to"
  Write-Host "     this PC every $SyncMinutes min so NetScope can read it."
  Write-Host ""
  Write-Host "  POSSIBLE EFFECTS / RISKS:" -ForegroundColor White
  Write-Host "   - CPU/RAM load: on a weak router this can SLOW your internet"
  Write-Host "     speed or make the router sluggish. Watch performance after."
  Write-Host "   - Storage: small-flash routers may not have room; install will"
  Write-Host "     fail safely with a space error if so (nothing half-broken)."
  Write-Host "   - It changes router config (adds a service + config files)."
  Write-Host "     The uninstall action reverses all of it."
  Write-Host "   - Requires root SSH access to the router."
  Write-Host ""
  Write-Host "  This does NOT change firewall rules, does NOT block devices,"
  Write-Host "  and does NOT touch your ISP settings. Detection only."
  Write-Host ""
  Write-Host "  To undo everything later:  -Action uninstall" -ForegroundColor Gray
  Write-Host "  ============================================================" -ForegroundColor Yellow
  Write-Host ""

  if ($Yes) { Ok "Confirmation skipped (-Yes)."; return }
  $answer = Read-Host "  Type INSTALL to proceed, or anything else to cancel"
  if ($answer -ne "INSTALL") { Warn "Cancelled. Nothing was changed."; exit 0 }
}

# --------------------------------------------------------------------------- #
# Router pre-flight
# --------------------------------------------------------------------------- #
function Test-Router {
  Info "Checking router at $Router (you'll be asked for its SSH password)..."
  $probe = @'
if [ ! -f /etc/openwrt_release ]; then echo "NOT_OPENWRT"; exit 0; fi
. /etc/openwrt_release 2>/dev/null
echo "OPENWRT $DISTRIB_RELEASE"
echo "FREE_OVERLAY_KB $(df /overlay 2>/dev/null | awk 'NR==2{print $4}')"
echo "FREE_TMP_KB $(df /tmp 2>/dev/null | awk 'NR==2{print $4}')"
echo "MEM_FREE_KB $(awk '/MemAvailable/{print $2}' /proc/meminfo)"
'@
  $out = Invoke-RouterSSH $probe
  if ($out -match "NOT_OPENWRT") {
    Fail "This router is not running OpenWrt. Suricata can't be installed on it."
    exit 1
  }
  if (-not ($out -match "OPENWRT")) {
    Fail "Could not reach the router over SSH (check IP, that SSH is enabled, and the password)."
    Write-Host ($out | Out-String) -ForegroundColor DarkGray
    exit 1
  }
  Write-Host ($out | Out-String) -ForegroundColor DarkGray
  $overlay = [int](($out | Select-String "FREE_OVERLAY_KB (\d+)").Matches.Groups[1].Value 2>$null)
  if ($overlay -and $overlay -lt 8000) {
    Warn "Router has little free storage (${overlay} KB). Suricata may not fit; install will error out safely if so."
  }
  Ok "OpenWrt router reachable."
}

# --------------------------------------------------------------------------- #
# Install
# --------------------------------------------------------------------------- #
function Install-RouterSuricata {
  $remote = @"
set -e
echo '--- updating package lists ---'
opkg update >/dev/null 2>&1 || { echo 'OPKG_UPDATE_FAILED'; exit 2; }
echo '--- installing suricata (this can take a minute) ---'
if ! opkg install suricata >/tmp/ns_install.log 2>&1; then
  tail -n 3 /tmp/ns_install.log
  echo 'INSTALL_FAILED'; exit 3
fi
mkdir -p /tmp/suricata
CONF=/etc/suricata/suricata.yaml
if [ -f "\$CONF" ]; then
  cp -n "\$CONF" "\$CONF.netscope.bak" 2>/dev/null || true
  sed -i "s|default-log-dir:.*|default-log-dir: /tmp/suricata/|" "\$CONF"
fi
# Best-effort: set the monitored interface if the config uses af-packet.
sed -i "0,/interface:.*/s||interface: $Interface|" "\$CONF" 2>/dev/null || true
[ -x /etc/init.d/suricata ] && /etc/init.d/suricata enable 2>/dev/null || true
[ -x /etc/init.d/suricata ] && /etc/init.d/suricata restart 2>/dev/null || true
sleep 2
if [ -f "$RemoteEve" ] || pgrep suricata >/dev/null 2>&1; then
  echo 'SURICATA_RUNNING'
else
  echo 'SURICATA_INSTALLED_NOT_CONFIRMED'
fi
"@
  Info "Installing Suricata on the router..."
  $out = Invoke-RouterSSH $remote
  Write-Host ($out | Out-String) -ForegroundColor DarkGray
  if ($out -match "INSTALL_FAILED") { Fail "Install failed on the router (likely not enough storage). Nothing was started."; exit 3 }
  if ($out -match "OPKG_UPDATE_FAILED") { Fail "Router could not reach the package servers (check its internet)."; exit 2 }

  New-Item -ItemType Directory -Force -Path $RouterLogDir | Out-Null
  & $Python -m netscope.envfile "NETSCOPE_SURICATA_EVE=$LocalEve" | Out-Null
  Ok "NetScope will read router alerts from $LocalEve"

  Sync-RouterLogs
  Register-SyncTask
  Ok "Done. Restart NetScope (python -m netscope) and open the Security tab."
  if ($out -match "NOT_CONFIRMED") {
    Warn "Suricata installed but I couldn't confirm it's running. Check on the router: logread | grep -i suricata"
  }
}

# --------------------------------------------------------------------------- #
# Uninstall
# --------------------------------------------------------------------------- #
function Uninstall-RouterSuricata {
  if (-not $Yes) {
    $a = Read-Host "Remove Suricata from router $Router and stop log syncing? Type YES to confirm"
    if ($a -ne "YES") { Warn "Cancelled."; exit 0 }
  }
  $remote = @'
[ -x /etc/init.d/suricata ] && /etc/init.d/suricata stop 2>/dev/null || true
[ -x /etc/init.d/suricata ] && /etc/init.d/suricata disable 2>/dev/null || true
opkg remove suricata --autoremove >/dev/null 2>&1 || true
[ -f /etc/suricata/suricata.yaml.netscope.bak ] && mv /etc/suricata/suricata.yaml.netscope.bak /etc/suricata/suricata.yaml 2>/dev/null || true
rm -rf /tmp/suricata 2>/dev/null || true
echo REMOVED
'@
  Info "Removing Suricata from the router..."
  $out = Invoke-RouterSSH $remote
  Write-Host ($out | Out-String) -ForegroundColor DarkGray

  Unregister-ScheduledTask -TaskName "NetScope-RouterLogSync" -Confirm:$false -ErrorAction SilentlyContinue
  & $Python -m netscope.envfile "NETSCOPE_SURICATA_EVE=" | Out-Null
  Ok "Suricata removed from router, log-sync task removed, NetScope pointer cleared."
}

# --------------------------------------------------------------------------- #
# Status / sync
# --------------------------------------------------------------------------- #
function Get-RouterStatus {
  $remote = @'
if pgrep suricata >/dev/null 2>&1; then echo "RUNNING"; else echo "NOT_RUNNING"; fi
opkg list-installed 2>/dev/null | grep -q "^suricata" && echo "INSTALLED" || echo "NOT_INSTALLED"
[ -f /tmp/suricata/eve.json ] && echo "LOG_PRESENT ($(wc -l < /tmp/suricata/eve.json) lines)" || echo "NO_LOG_YET"
'@
  Info "Router IDS status:"
  Invoke-RouterSSH $remote | ForEach-Object { Write-Host "   $_" }
}

function Sync-RouterLogs {
  New-Item -ItemType Directory -Force -Path $RouterLogDir | Out-Null
  Info "Pulling alert log from router..."
  scp -o StrictHostKeyChecking=accept-new "$User@${Router}:$RemoteEve" "$LocalEve" 2>$null
  if (Test-Path $LocalEve) { Ok "Synced to $LocalEve" }
  else { Warn "No alert log yet (Suricata may still be starting, or no alerts fired). It'll appear on the next sync." }
}

function Register-SyncTask {
  if (-not $Yes) {
    $a = Read-Host "Create a scheduled task to auto-sync router alerts every $SyncMinutes min? (y/N)"
    if ($a -notin @("y", "Y")) { Warn "Skipped auto-sync. Run '-Action sync' manually when you want fresh alerts."; return }
  }
  $self = $MyInvocation.MyCommand.Path
  if (-not $self) { $self = Join-Path $PSScriptRoot "setup-router-ids.ps1" }
  $cmd = "powershell -ExecutionPolicy Bypass -File `"$self`" -Action sync -Router $Router -User $User -Yes"
  $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $SyncMinutes)
  $act = New-ScheduledTaskAction -Execute "powershell" -Argument "-ExecutionPolicy Bypass -File `"$self`" -Action sync -Router $Router -User $User -Yes"
  try {
    Register-ScheduledTask -TaskName "NetScope-RouterLogSync" -Trigger $trigger -Action $act -Force | Out-Null
    Ok "Auto-sync task created (every $SyncMinutes min)."
  } catch {
    Warn "Could not create scheduled task ($($_.Exception.Message)). Run '-Action sync' manually instead."
  }
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
Test-SshClient
Write-Host ""
Info "NetScope router IDS - action: $Action - router: $Router"

switch ($Action) {
  "install"   { Show-Effects; Test-Router; Install-RouterSuricata }
  "uninstall" { Uninstall-RouterSuricata }
  "status"    { Get-RouterStatus }
  "sync"      { Sync-RouterLogs }
}
