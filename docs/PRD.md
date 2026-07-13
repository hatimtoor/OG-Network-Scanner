# NetScope — Product Requirements Document (PRD)

**Version:** 1.1
**Date:** 2026-07-14
**Owner:** hatimtoor
**Status:** Draft for build planning
**North star:** Security Onion (open-source NSM/threat-hunting) + the usability of
home tools (Fing/Firewalla/UniFi), delivered as one friendly, self-hostable app.

---

## 1. Vision

NetScope should let anyone — from a home user to a small SOC — **see every device on
their network, understand exactly what each one is, watch what it's doing, and be
warned (and able to act) when something is wrong** — from a single, beautiful,
self-hosted dashboard, with no per-seat licensing.

Today NetScope is a strong **discovery + identification + light IDS-ingestion** tool.
The gap to "platform" status is in **behavioral detection, a real data pipeline,
host visibility, incident response, and threat intelligence** — the areas below.

---

## 2. Reference platforms surveyed

| Platform | Category | What it does well |
|---|---|---|
| **Security Onion 2.4/3.0** | Open NSM / threat hunting | Suricata (NIDS) + Zeek (metadata/protocol logs) + **Strelka** (file analysis) + **full PCAP** + Elastic (search/dashboards) + **Elastic Agent/osquery** host visibility + **Cases** + **Playbooks/Guided Analysis** + **OpenCanary honeypots** + AI assistant |
| **Wazuh** | Open XDR/SIEM | Host **agent**: FIM, config assessment (SCA), **vulnerability detection**, software inventory, log analysis, **MITRE ATT&CK** mapping, **active response** (auto-block), compliance reports |
| **Suricata / Zeek / Corelight** | Sensors | Signature IDS, protocol metadata, file extraction, JA3/TLS, DNS logs; Corelight = enterprise Zeek/Suricata sensors |
| **Darktrace / Vectra (NDR)** | Behavioral detection | Unsupervised ML "pattern of life" baselining, anomaly + kill-chain detection **without rules**, beaconing/exfil/lateral-movement detection |
| **Palo Alto / Fortinet (NGFW)** | Inline security | **IPS blocking**, App-ID, URL filtering, **TLS decryption**, **sandboxing** (WildFire/FortiSandbox) |
| **Fing / Firewalla / UniFi** | Home/prosumer | New-device alerts, **per-device bandwidth & controls**, parental controls, device **blocking/quarantine**, presence, speed test, gorgeous UX |
| **Nmap / OpenVAS-Nessus** | Scanners | Deep port/OS/service scan; full **vulnerability scanning** with CVE/CVSS |

---

## 3. NetScope today (current capabilities)

- **Discovery:** ARP + ping sweep, multi-subnet, `arp -a` fallback, multicast filtering.
- **Identification:** multi-signal (OUI, mDNS, ports, TTL, hostname) with confidence;
  handles randomized MACs.
- **Deep enrichment:** UPnP/SSDP model+serial, mDNS TXT, banner/HTTP/TLS grab, SNMP,
  passive DHCP/LLDP fingerprint, **CVE correlation (NVD)**.
- **Ports/services:** Nmap + socket fallback, risky-port flagging.
- **Monitoring:** continuous rescans, **new-device + risky-port + CVE alerts**,
  desktop/email/webhook notifications.
- **Traffic:** host throughput chart, active connections table.
- **Security:** VirusTotal IP/hash, **Suricata/Zeek log ingestion**, OpenWrt router
  installer, YARA file scan.
- **UX/data:** web dashboard (WebSocket live), topology map, device history/naming,
  SQLite storage, CSV export, HTML report.

---

## 4. Gap analysis — what the platforms have that we don't

Legend: ✅ have · 🟡 partial · ❌ missing

| Capability | NetScope | Reference |
|---|---|---|
| Device discovery & inventory | ✅ | Fing/UniFi |
| Deep device identification (model/serial/CVE) | ✅ | (better than most) |
| Signature IDS (Suricata) | 🟡 ingest-only | Security Onion |
| Protocol metadata / connection logs (Zeek) | 🟡 ingest-only | Security Onion |
| **Full packet capture (PCAP) + retrieval** | ❌ | Security Onion |
| **Behavioral / ML anomaly detection** | ❌ | Darktrace/Vectra |
| **DNS analytics (tunneling/DGA/C2)** | ❌ | Zeek/NDR |
| **TLS/SNI/JA3 fingerprinting** | 🟡 cert only | Zeek/NDR |
| **Data pipeline + search/hunting UI** | 🟡 SQLite | Elastic/OpenSearch |
| **Host agent** (FIM, inventory, osquery, config) | ❌ | Wazuh/Elastic Agent |
| **Vulnerability scanning** (authenticated, deep) | 🟡 CVE-by-version | OpenVAS/Wazuh |
| **MITRE ATT&CK mapping** | ❌ | Wazuh/SO |
| **Case management / incident response** | ❌ | Security Onion Cases |
| **Playbooks / guided triage** | ❌ | Security Onion |
| **Active response / blocking / quarantine** | ❌ | Wazuh/Firewalla/NGFW |
| **Threat-intel feeds** (MISP/STIX/blocklists) | 🟡 VT only | SO/Wazuh |
| **File sandboxing** | 🟡 VT hash | WildFire/Cuckoo/Strelka |
| **Honeypots** | ❌ | Security Onion (OpenCanary) |
| **Per-device bandwidth & controls** | 🟡 host-only | Firewalla/UniFi |
| **Parental controls / scheduling** | ❌ | Firewalla/UniFi |
| **Compliance reporting** (PCI/HIPAA/GDPR) | ❌ | Wazuh |
| **Multi-user / RBAC** | ❌ | all enterprise |
| **AI assistant / natural-language triage** | ❌ | Security Onion 2.4.160+ |
| **Scheduled reports (email/PDF)** | 🟡 manual HTML | most |
| **Speed test / connectivity monitoring** | ❌ | Firewalla |

---

## 5. Product requirements

Priorities: **P0** = core parity / highest value, **P1** = strong differentiator,
**P2** = advanced / enterprise. Each requirement lists intent + acceptance criteria.

### 5.1 Sensor & capture layer (P0)

- **R1 — Bundled sensor mode.** Ship a first-class sensor that runs Suricata (+ Zeek)
  and streams into NetScope, not just log-tailing. *Accept:* one command turns a
  host/Pi/mini-PC into a sensor; alerts + Zeek logs appear in the dashboard.
- **R2 — Full packet capture.** Rolling PCAP with size/time retention; per-alert
  "download PCAP" and time/host/BPF search. *Accept:* click an alert → get the
  related packets.
- **R3 — DNS analytics.** Parse DNS (from Zeek/passive), flag DGA-like domains,
  tunneling (high TXT/volume), and known-bad domains. *Accept:* suspicious DNS shows
  as events with reasons.
- **R4 — TLS/JA3 fingerprinting.** JA3/JA3S + SNI extraction to identify client apps
  and destinations even without decryption. *Accept:* connections list shows SNI + JA3.

### 5.2 Behavioral analytics / anomaly detection (P0/P1)

- **R5 — Baselining ("pattern of life").** Learn each device's normal peers, ports,
  bandwidth, and active hours. *Accept:* per-device baseline visible after a learning
  window.
- **R6 — Anomaly detections (rules-light).** Beaconing (regular callbacks), data
  exfiltration (unusual upload volume), new external service, port-scan/lateral
  movement, off-hours activity, new-country destination. *Accept:* each fires a scored,
  explained alert. **P1:** unsupervised ML scoring on top of the heuristics.

### 5.3 Data pipeline, search & hunting (P0)

- **R7 — Scalable event store.** Move beyond SQLite for events/flows/logs (OpenSearch
  or DuckDB/embedded) with retention policies. *Accept:* millions of events searchable.
- **R8 — Hunting UI.** Query/filter across devices, connections, DNS, alerts; saved
  queries; time-range. *Accept:* free-text + field filters return results fast.
- **R9 — Dashboards.** Configurable widgets (top talkers, protocols, alert trends).

### 5.4 Host visibility / agent (P1)

- **R10 — Lightweight host agent.** Optional cross-platform agent: software/patch
  inventory, **file integrity monitoring**, logged-in users, listening ports,
  config/hardening checks. *Accept:* agent enrolls over the dashboard; host facts +
  FIM alerts appear. (osquery-style, Wazuh-inspired.)
- **R11 — Authenticated vuln checks.** Use inventory to match CVEs precisely (CPE),
  beyond banner-version guessing.

### 5.5 Detection engineering & response (P0/P1)

- **R12 — MITRE ATT&CK mapping.** Tag every detection with technique IDs; coverage map.
- **R13 — Case management.** Group alerts into cases with status/owner/notes/timeline;
  export. *Accept:* analyst can triage → escalate → close.
- **R14 — Playbooks / guided triage.** Per-detection "what this means / what to do";
  optional AI summary. *Accept:* each alert links a playbook.
- **R15 — Active response.** Quarantine a device (via router API/OpenWrt firewall or
  ARP-level isolation), block an IP/domain, kill a connection; all reversible + logged.
  *Accept:* one click isolates a device; one click restores it. **Consent + audit.**

### 5.6 Threat intelligence (P1)

- **R16 — Feeds.** MISP / STIX-TAXII / plaintext blocklists (IP/domain/hash) with
  auto-refresh; match against live traffic + inventory. *Accept:* a hit on a feed IOC
  raises a critical alert.
- **R17 — File analysis.** Extract files from traffic (Zeek/Strelka-style) → hash →
  VirusTotal / optional sandbox (Cuckoo). *Accept:* extracted EXE/ZIP gets a verdict.

### 5.7 Home / prosumer features (P1)

- **R18 — True per-device bandwidth.** Via router SNMP/API or sensor flow accounting
  (not just this host). *Accept:* per-device up/down + history.
- **R19 — Controls.** Pause internet / schedule (parental controls) / block device,
  via router integration. **P2** for stock routers (limited).
- **R20 — Presence & speed test.** Who's home (device presence), periodic WAN speed test.

### 5.8 Platform, reporting & delivery (P1/P2)

- **R21 — Scheduled reports.** Email/PDF on a schedule; weekly security summary.
- **R22 — Compliance packs.** PCI/HIPAA/GDPR-style report templates. **P2**
- **R23 — Multi-user + RBAC.** Login, roles (viewer/analyst/admin), audit log. **P2**
- **R24 — AI assistant.** Natural-language questions ("what's talking to Russia?"),
  alert summaries, guided next steps. **P2**
- **R25 — Packaging.** One-click Windows `.exe`, Docker image, and a Pi/mini-PC
  "appliance" image; auto-update.

---

## 6. Proposed architecture evolution (toward the Security Onion model)

```
                         +-------------------- NetScope Manager --------------------+
                         |  Web UI (dashboards, hunting, cases, playbooks, AI)      |
                         |  API + WebSocket                                         |
                         |  Detection engine (rules + heuristics + ML anomaly)      |
                         |  Event/flow store (OpenSearch or DuckDB) + retention     |
                         |  Threat-intel matcher · Case mgr · Response orchestrator |
                         +----------------^--------------------^--------------------+
                                          |                    |
                  logs/alerts/PCAP meta   |                    |  host facts / FIM
                                          |                    |
        +--------------- Sensor(s) -------+----+        +------ Host agents ------+
        | Suricata (NIDS) · Zeek (metadata)   |        | inventory · FIM · users |
        | full PCAP · file extraction · DNS   |        | listening ports · config|
        | passive fingerprinting              |        +-------------------------+
        | (on router / mirror port / inline)  |
        +-------------------------------------+
```

Key shifts from today: split **manager vs sensor vs agent**; replace SQLite with a
**search-grade store**; add a **detection engine** and **response orchestrator**.
Single-host mode (today's model) remains the zero-setup default; sensor/agents are
opt-in for depth.

---

## 7. Phased roadmap

- **Phase A (P0 — "real NSM"):** productionize sensor mode (R1), PCAP (R2), event
  store + hunting UI (R7–R9), DNS + JA3 (R3–R4), core behavioral heuristics (R6),
  MITRE tagging (R12), basic cases (R13).
- **Phase B (P1 — "response + intel"):** host agent + FIM (R10–R11), threat-intel
  feeds (R16), file extraction/sandbox (R17), active response/quarantine (R15),
  playbooks (R14), per-device bandwidth + controls (R18–R19), scheduled reports (R21).
- **Phase C (P2 — "platform"):** ML anomaly/pattern-of-life (R5 ML), honeypots,
  AI assistant (R24), RBAC/multi-user (R23), compliance packs (R22), appliance
  image + auto-update (R25).

---

## 8. Non-goals & constraints

- **Physics of switched networks:** deep traffic inspection of *other* devices needs a
  sensor at a vantage point (router / mirror port / inline). NetScope will make this
  easy but cannot bypass it on a locked stock router.
- **Not a replacement for a licensed enterprise SOC** on day one; the aim is
  Security-Onion-class capability with far better UX and a gentle on-ramp.
- **Privacy & legality:** authorized-use only; no MAC de-anonymization; response
  actions require explicit consent and are fully audited.
- **Resource honesty:** ML/PCAP/agents cost CPU/RAM/disk; features degrade gracefully
  and are opt-in.

---

## 9. Decisions (resolved)

1. **Event store — tiered.** Keep **SQLite** for transactional state (devices, cases,
   config). Add **DuckDB** (embedded, columnar) for high-volume analytics (flows, DNS,
   connections, events) that hunting/aggregation run over. Store interface is
   pluggable; **OpenSearch** is an optional backend for large sensor deployments only
   (its JVM/RAM cost breaks the "runs on a Pi / your PC" default).
2. **Host agent — build minimal ourselves.** Small cross-platform agent: software/patch
   inventory, listening ports, logged-in users, FIM on watched paths, hardening checks.
   Full **osquery** is an opt-in "advanced" mode, not the default (weight + management
   burden fights our simplicity).
3. **ML — heuristics first, ML later.** Ship explainable heuristic detections in
   Phase A (each with a "why"); add unsupervised anomaly **scoring on top** of baselines
   in Phase C. ML augments, never replaces, the explainable layer.
4. **Active-response router order — OpenWrt → UniFi → pfSense**, plus a router-agnostic
   **ARP-isolation fallback** (layer-2 cutoff from a sensor) for locked routers, shipped
   with explicit warnings + full audit.
5. **Appliance footprint.** Manager-only runs on anything (incl. the user's Windows PC).
   Home sensor: **Raspberry Pi 4/5, 4GB+ RAM, SSD** (good to a few hundred Mbps + modest
   PCAP). Heavy/gigabit + PCAP + ML: **x86 mini-PC, 4 cores / 8-16GB / SSD**. Honest cap:
   Suricata on a Pi tops out at a few hundred Mbps; line-rate gigabit needs x86.
