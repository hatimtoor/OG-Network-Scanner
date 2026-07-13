<#
.SYNOPSIS
  Analyze a packet capture (.pcap/.pcapng) with Zeek via Docker, writing logs
  where NetScope can read them.

.PARAMETER Pcap
  Path to the capture file to analyze.

.PARAMETER OutDir
  Directory to write Zeek logs into. Defaults to the project's zeek-logs folder
  (the same directory NetScope watches when NETSCOPE_ZEEK_DIR is set).

.EXAMPLE
  powershell -File scripts\zeek-process-pcap.ps1 -Pcap C:\captures\home.pcapng
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Pcap,
  [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $ProjectRoot "zeek-logs" }

if (-not (Test-Path $Pcap)) { Write-Host "[x] PCAP not found: $Pcap" -ForegroundColor Red; exit 1 }
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Write-Host "[x] Docker not found. Install Docker Desktop first." -ForegroundColor Red; exit 1
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$pcapFull = (Resolve-Path $Pcap).Path
$pcapDir = Split-Path $pcapFull
$pcapName = Split-Path $pcapFull -Leaf

Write-Host "[*] Running Zeek over $pcapName ..." -ForegroundColor Cyan
# -C ignores checksum offload errors common in host captures.
docker run --rm `
  -v "${OutDir}:/logs" `
  -v "${pcapDir}:/pcap:ro" `
  -w /logs `
  zeek/zeek:latest zeek -C -r "/pcap/$pcapName"

if ($LASTEXITCODE -eq 0) {
  Write-Host "[+] Zeek logs written to $OutDir" -ForegroundColor Green
  Write-Host "    NetScope's Security tab will show notice.log alerts on its next poll." -ForegroundColor Gray
} else {
  Write-Host "[x] Zeek exited with code $LASTEXITCODE" -ForegroundColor Red
}
