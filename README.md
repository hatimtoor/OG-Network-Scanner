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
