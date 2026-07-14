# 🛰️ NetScope — Network Discovery & Security Monitor

NetScope is a **defensive tool for scanning and protecting your own network**. It
runs a small always-on service on your PC (or a spare mini-PC / Raspberry Pi) and
gives you a live web dashboard that shows every device connected to your network,
what each device is, and alerts you the moment something new appears.

It is the same category of tool as Nmap, Fing, and Angry IP Scanner — built for
network owners and administrators.

---

## ⚠️ Authorized use only

Use NetScope **only on networks you own or are explicitly authorized to scan**.
Active scanning and OS fingerprinting of networks you do not control may be
against the law and against your ISP's terms of service. You are responsible for
how you use this tool.

NetScope intentionally does **not** attempt to defeat MAC-address randomization or
otherwise de-anonymize devices.

---

## Features (v1)

- **Automatic device discovery** — finds every live host on your subnet (IP + MAC + hostname).
- **Smart device identification** — combines MAC vendor (OUI), mDNS/Bonjour, open
  ports, TTL, and hostname to guess each device's **type** (phone, computer, TV,
  printer, IoT, camera, router…) and **OS**, with a confidence score. Works even
  when phones use randomized MAC addresses.
- **Interactive topology map** — your router at the center with all devices around it.
- **Port & service scan** — shows open ports per device and flags risky ones
  (Telnet, SMB, RDP, VNC…). Uses Nmap when installed, otherwise a built-in scanner.
- **Continuous monitoring + new-device alerts** — rescans on an interval and raises
  an alert (and desktop/email/webhook notification) when an unknown device joins.
- **Device history & naming** — rename devices, mark them trusted, see first/last seen.
- **Live dashboard** — updates in real time over WebSocket.

### Traffic (v2)

- **Live throughput chart** — real-time upload/download of this machine.
- **Active connections table** — every outbound connection with process name,
  remote IP/port, and the LAN device it maps to.
- **CSV export** — one-click export of devices and alerts.

### Security (v3)

- **IP reputation** — check any IP against **VirusTotal** (set `NETSCOPE_VT_API_KEY`).
  Optionally auto-checks the external IPs your machine talks to.
- **File scan** — SHA-256 hash + VirusTotal reputation + optional **YARA** rules
  (`pip install yara-python`, set `NETSCOPE_YARA_RULES`).
- **IDS sensor ingestion** — if you run **Suricata** or **Zeek** on a mirror/SPAN
  port, point NetScope at their logs (`NETSCOPE_SURICATA_EVE`, `NETSCOPE_ZEEK_DIR`)
  and their alerts appear in the Security tab and drive notifications.

All security features are optional and degrade gracefully when unconfigured.

### NSM platform (Phase A–C)

NetScope has grown from a scanner into a Security-Onion-class monitoring platform:

- **Flow store + Hunting** — a DuckDB analytics store records connections over time;
  the **Hunting** tab searches flows with top-talker and per-device bandwidth views.
- **Behavioral detection** — explainable heuristics flag port/host scanning, C2
  **beaconing**, and **data exfiltration**, each tagged with **MITRE ATT&CK** techniques.
- **DNS + TLS analytics** — DGA/tunnelling domain detection and JA3/SNI fingerprinting.
- **Case management** — group alerts into investigations with status, notes, and
  linked events; every alert carries a **playbook** (what it means / what to do).
- **Host agent** — software inventory, listening ports, logged-in users, hardening
  checks, and **file-integrity monitoring** for the machine it runs on.
- **Threat-intel feeds** — auto-refreshed IP/domain blocklists matched against traffic.
- **Active response** — quarantine a device (OpenWrt firewall or ARP isolation),
  consented and reversible, with timed "pause for N minutes".
- **Anomaly detection + honeypots** — statistical throughput-spike detection and decoy
  ports that alert on any probe.
- **Compliance packs** — PCI/CIS/GDPR-style control scorecard + printable report.
- **Optional login** (`NETSCOPE_AUTH=true`) and an **AI assistant** (Claude, or a
  built-in rule-based fallback) that answers natural-language questions about your network.

### Advanced coverage (closing the enterprise gaps)

- **Pattern-of-life anomaly** — learns each device's normal ports/peers, then flags new
  services and peer fan-out spikes (explainable NDR-style detection).
- **Packet index (mini-Arkime)** — index captured PCAPs and search packets by IP / port /
  protocol; download the matching capture.
- **MISP + STIX/TAXII** — consume the formal threat-sharing formats (+ hash IOCs).
- **User-Agent identification** — from Zeek `http.log` and decrypted HTTPS.
- **Malware sandboxing** — Cuckoo submission + VirusTotal behaviour verdicts (dynamic
  analysis on top of static hash/VT/YARA).
- **Decrypted HTTPS** — ingest **mitmproxy** output (`scripts/mitm-jsonl-addon.py`) to see
  host/path/User-Agent per client (the same MITM approach an NGFW uses).
- **Router bandwidth via SNMP** — per-interface throughput from the router's ifTable.
- **Dashboards + global search** — a Dashboard tab (alert trends, MITRE coverage, top
  ports, throughput) and a search box across devices, alerts, and flows.

Config for these: `NETSCOPE_MISP_URL/_KEY`, `NETSCOPE_STIX_URL`, `NETSCOPE_CUCKOO_URL`,
`NETSCOPE_MITM_LOG`, `NETSCOPE_SNMP_ROUTER` (all optional).

### Deep device inspection

Beyond type/OS identification, NetScope can pull deep detail per device. Light
enrichment runs automatically during scans; heavy probes run on demand via the
**Deep Scan** button in a device's detail panel.

- **Exact model / serial / firmware** — from UPnP/SSDP descriptions and mDNS TXT
  records (auto, no hardware needed).
- **Service & version fingerprint** — banner grabbing + HTTP `Server` header/title
  + TLS certificate common name for each open port.
- **SNMP system info** — description, name, uptime, location from printers, APs,
  NAS and managed switches (community configurable via `NETSCOPE_SNMP_COMMUNITY`).
- **Passive OS fingerprint** — DHCP option-55 and LLDP are broadcast, so NetScope
  fingerprints OS and infrastructure gear from your PC with no mirror port.
- **Vulnerability (CVE) correlation** — detected software/versions are checked
  against the NVD database; high/critical findings raise alerts. Set
  `NETSCOPE_NVD_API_KEY` for a higher rate limit (optional).

---

## Requirements

- **Python 3.11+**
- **Npcap** (Windows) — enables fast ARP scanning. Install from https://npcap.com
  (tick "WinPcap API-compatible mode"). *Optional* — NetScope falls back to the
  Windows ARP table if it's missing.
- **Nmap** *(optional)* — enables OS/service/version detection. https://nmap.org/download
  Without it, NetScope uses a built-in TCP port scanner.

## Install

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

## Run

```bash
python -m netscope
```

The dashboard opens automatically at http://127.0.0.1:8000

> **Tip:** For best results (raw ARP + Nmap OS detection) run the terminal
> **as Administrator** on Windows / with `sudo` on Linux. It still works without
> elevation using the ping-sweep + ARP-table fallback.

### Other ways to run it

```bash
# Docker (LAN discovery works best on a Linux host / Raspberry Pi)
docker compose up -d          # then open http://localhost:8000

# Standalone Windows .exe (no Python needed to run it)
powershell -File scripts\build-exe.ps1   # produces dist\netscope.exe
```

---

## Configuration

Create a `.env` file in the project root (all optional):

```ini
NETSCOPE_HOST=127.0.0.1
NETSCOPE_PORT=8000
NETSCOPE_SUBNET=            # leave blank to auto-detect, or e.g. 192.168.1.0/24
NETSCOPE_SCAN_INTERVAL=120  # seconds between automatic rescans
NETSCOPE_USE_NMAP=true

# Notifications (optional)
NETSCOPE_NOTIFY_DESKTOP=true
NETSCOPE_WEBHOOK_URL=       # Discord/Slack webhook, or Telegram sendMessage URL
NETSCOPE_SMTP_HOST=
NETSCOPE_SMTP_PORT=587
NETSCOPE_SMTP_USER=
NETSCOPE_SMTP_PASS=
NETSCOPE_SMTP_TO=

# Traffic (v2)
NETSCOPE_TRAFFIC_INTERVAL=3  # seconds between throughput samples

# Security (v3) — all optional
NETSCOPE_VT_API_KEY=         # VirusTotal API key (free tier works)
NETSCOPE_THREAT_AUTOCHECK=false  # auto-check external IPs this host talks to
NETSCOPE_SURICATA_EVE=       # path to Suricata eve.json
NETSCOPE_ZEEK_DIR=           # path to Zeek log directory
NETSCOPE_YARA_RULES=         # path to a .yar rules file (needs yara-python)

# Platform (Phase A-C) — all optional
NETSCOPE_FLOW_RECORD=true         # record connections into the flow store
NETSCOPE_BEHAVIORAL=true          # scan/beacon/exfil detection
NETSCOPE_ANOMALY=true             # statistical throughput anomaly
NETSCOPE_FEEDS=true               # threat-intel blocklists
NETSCOPE_HOST_AGENT=true          # host facts + FIM
NETSCOPE_FIM_PATHS=               # comma-separated files/dirs to watch
NETSCOPE_PCAP=false               # rolling packet capture (heavy; needs Npcap)
NETSCOPE_HONEYPOT=false           # decoy listener ports
NETSCOPE_HONEYPOT_PORTS=23,2323,3389,8081
NETSCOPE_REPORT_HOURS=0           # >0 = email the report every N hours
NETSCOPE_AUTH=false               # require login
NETSCOPE_PASSWORD=                # login password (when auth on)
NETSCOPE_ANTHROPIC_KEY=           # enables the Claude AI assistant (pip install anthropic)

# Misc
NETSCOPE_OPEN_BROWSER=true   # set false to not auto-open the dashboard
```

---

## Deep packet inspection setup (Suricata + Zeek)

NetScope doesn't reimplement an IDS — it drives the industry-standard engines and
shows their results. A one-command script installs and wires them up:

```powershell
# Set up BOTH engines and point NetScope at their logs
powershell -ExecutionPolicy Bypass -File scripts\setup-ids.ps1

# Just Suricata, and start live monitoring (run terminal as Administrator)
powershell -ExecutionPolicy Bypass -File scripts\setup-ids.ps1 -Tool suricata -Start

# Analyze a capture file with Zeek
powershell -File scripts\zeek-process-pcap.ps1 -Pcap C:\captures\home.pcapng
```

What it does:
- **Suricata** — installs it (winget `OISF.Suricata`), refreshes the Emerging
  Threats ruleset, auto-detects your active adapter (via Npcap), writes
  `NETSCOPE_SURICATA_EVE` into `.env`, and can start live IDS monitoring.
- **Zeek** — has no native Windows build, so it runs via **Docker**; the script
  pulls the `zeek/zeek` image, creates a `zeek-logs/` folder, points
  `NETSCOPE_ZEEK_DIR` at it, and analyzes any PCAP you give it.

After running it, restart `python -m netscope` and open the **Security** tab —
IDS alerts stream in and drive notifications.

> **Visibility note:** to inspect *other devices'* traffic (not just this PC's),
> the engine must run where it can see it — on your router, on a PC attached to a
> switch **mirror/SPAN port**, or against a PCAP captured there. On this PC alone
> it inspects this machine's own traffic, which still catches malware your
> computer communicates with.

### Installing on an OpenWrt router (over Wi-Fi, via SSH)

If your router runs **OpenWrt**, NetScope can install Suricata directly on it so
it sees the whole network — done entirely over the network (Wi-Fi is fine):

```powershell
# Explains the effects, asks for consent, then installs over SSH
powershell -ExecutionPolicy Bypass -File scripts\setup-router-ids.ps1 -Router 192.168.1.1

powershell -File scripts\setup-router-ids.ps1 -Action status      # check it
powershell -File scripts\setup-router-ids.ps1 -Action uninstall   # remove it cleanly
```

- **Consent first** — it prints exactly what it will do and the risks, then waits
  for you to type `INSTALL`.
- **Detection only** — Suricata watches and alerts; it never blocks your traffic.
- **Flash-safe** — logs go to the router's RAM (`/tmp`), not its flash.
- **Auto-sync** — a scheduled task pulls the router's alerts to this PC so the
  Security tab shows them.
- **Clean uninstall** — `-Action uninstall` stops the service, removes the
  package, restores the original config, deletes the sync task, and clears the
  NetScope pointer.

> Only works on **OpenWrt** (not stock ISP routers). A weak router running
> Suricata may slow your internet — watch performance and uninstall if needed.

## How it works

```
python -m netscope
   │
   ├── FastAPI server  ──►  web dashboard (http://127.0.0.1:8000)
   │        ▲
   │        │ REST + WebSocket (live updates)
   │
   └── Background Monitor (every NETSCOPE_SCAN_INTERVAL seconds)
            ├── discovery.py   ping sweep + ARP table + scapy ARP → live hosts
            ├── mdns.py        Bonjour/mDNS service discovery
            ├── portscan.py    Nmap (if present) or built-in socket scan
            ├── identify.py    fuse signals → device type + OS + confidence
            └── store.py       SQLite persistence + new-device / risky-port events
```

## Roadmap

- **v2** — per-device bandwidth, connection log, scheduled scans, exports.
- **v3** — optional sensor mode (Suricata + Zeek on a mirror port) for deep packet
  inspection, IDS, and malware detection; file reputation via VirusTotal + YARA.
- **v4** — business (multi-subnet, asset inventory, reporting) and SOC tiers.

## License

For authorized, personal/administrative use. See the disclaimer above.
