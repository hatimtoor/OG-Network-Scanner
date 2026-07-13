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
```

---

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
