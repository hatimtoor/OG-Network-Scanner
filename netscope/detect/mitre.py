"""Minimal MITRE ATT&CK technique reference used to tag detections.

Only the techniques NetScope's detections reference are included; each detection
carries a technique id + name so the UI can show coverage and link out.
"""
from __future__ import annotations

TECHNIQUES = {
    "T1046": "Network Service Discovery",
    "T1071": "Application Layer Protocol (C2)",
    "T1071.001": "Web Protocols (C2)",
    "T1571": "Non-Standard Port",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1041": "Exfiltration Over C2 Channel",
    "T1568": "Dynamic Resolution (DGA)",
    "T1572": "Protocol Tunneling",
    "T1595": "Active Scanning",
    "T1021": "Remote Services",
    "T1190": "Exploit Public-Facing Application",
    "T1565": "Data Manipulation",
    "T1070": "Indicator Removal (file deleted)",
    "T1105": "Ingress Tool Transfer",
    "T1046-scan": "Network Service Discovery",
}


def name(technique_id: str) -> str:
    return TECHNIQUES.get(technique_id, technique_id)


def url(technique_id: str) -> str:
    base = technique_id.split(".")[0]
    if "." in technique_id:
        sub = technique_id.split(".")[1]
        return f"https://attack.mitre.org/techniques/{base}/{sub}/"
    return f"https://attack.mitre.org/techniques/{base}/"
