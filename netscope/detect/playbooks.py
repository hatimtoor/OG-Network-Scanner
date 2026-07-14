"""Playbooks: guided triage for each detection/alert type (R14).

Maps an event type to a short "what it means / what to check / what to do"
playbook so a non-expert can act on an alert. Surfaced in the dashboard.
"""
from __future__ import annotations

_PLAYBOOKS: dict[str, dict] = {
    "new_device": {
        "summary": "A device not seen before joined the network.",
        "steps": [
            "Identify it — check the vendor, hostname, and open ports on its card.",
            "If you recognise it, open the device and mark it 'trusted' (and rename it).",
            "If you don't, disconnect it or quarantine it, and change your Wi-Fi password.",
        ],
    },
    "port_alert": {
        "summary": "A device is exposing a risky service (Telnet/SMB/RDP/VNC).",
        "steps": [
            "Confirm the service is intended on that device.",
            "Disable it or firewall it if not needed; patch if it must stay.",
            "For RDP/VNC, require strong auth and restrict to the LAN.",
        ],
    },
    "port_scan": {
        "summary": "A host contacted many external IPs (scanning/sweeping).",
        "steps": [
            "Identify the process on the local host driving the connections.",
            "If it's malware or unexpected, isolate the host and scan it.",
            "If legitimate (e.g. a P2P app or scanner), note it as expected.",
        ],
    },
    "vertical_scan": {
        "summary": "Many ports probed on one destination — a port scan.",
        "steps": [
            "Check whether the scan originated from your host or a LAN device.",
            "If unexpected, treat the source as compromised and investigate.",
        ],
    },
    "beaconing": {
        "summary": "Steady, regular callbacks to one external endpoint (possible C2).",
        "steps": [
            "Look up the destination IP/domain reputation (Security tab → IP check).",
            "Identify the process making the callbacks.",
            "If the destination is untrusted, quarantine the device and remove the process.",
        ],
    },
    "data_exfil": {
        "summary": "A large volume was uploaded to an external host.",
        "steps": [
            "Confirm whether the transfer is expected (backup, cloud sync, upload).",
            "If not, quarantine the device immediately and preserve evidence (PCAP).",
            "Rotate any credentials that device had access to.",
        ],
    },
    "dns_anomaly": {
        "summary": "A suspicious domain was queried (DGA or tunneling).",
        "steps": [
            "Check which host made the query and what process.",
            "Block the domain and investigate the host for malware.",
        ],
    },
    "threat_feed": {
        "summary": "Traffic matched a known-bad indicator from a threat feed.",
        "steps": [
            "Treat as high-confidence: identify the host and process.",
            "Quarantine the device and run a full malware scan.",
        ],
    },
    "malware_file": {
        "summary": "A file extracted from traffic was flagged as malicious.",
        "steps": [
            "Do not open the file. Identify which device downloaded it.",
            "Quarantine that device and scan it; block the source.",
        ],
    },
    "vulnerability": {
        "summary": "A device runs software with a known CVE.",
        "steps": [
            "Confirm the version and CVE severity.",
            "Patch/update the device firmware or software.",
            "If unpatchable, isolate it on a separate VLAN.",
        ],
    },
    "fim": {
        "summary": "A watched file was modified or deleted.",
        "steps": [
            "Confirm the change was expected (an update or your own edit).",
            "If not, treat the host as potentially compromised and investigate.",
        ],
    },
    "ids_alert": {
        "summary": "The IDS (Suricata/Zeek) matched a threat signature.",
        "steps": [
            "Open the alert's signature to understand the threat.",
            "Pull the related PCAP and identify the hosts involved.",
        ],
    },
}


def for_type(event_type: str) -> dict | None:
    return _PLAYBOOKS.get(event_type)


def all_playbooks() -> dict:
    return _PLAYBOOKS
