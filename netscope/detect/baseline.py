"""Pattern-of-life baselining (R5, ML-lite).

Learns each device's normal behaviour (the external ports it uses and how many
remote peers it talks to) during a learning window, then flags deviations:
a device suddenly using a service it never used, or a sharp jump in the number
of external peers. This is the explainable, per-device analogue of an NDR's
"pattern of life" — statistical novelty, not a black box.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..config import settings
from ..db import analytics

_BASELINE = Path(settings.db_path).resolve().parent / "baselines.json"


@dataclass
class Anomaly:
    key: str
    title: str
    description: str
    severity: str = "warning"
    score: int = 0
    mitre_id: str = ""

    def to_dict(self) -> dict:
        return self.__dict__


def _load() -> dict:
    try:
        return json.loads(_BASELINE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save(data: dict) -> None:
    try:
        _BASELINE.write_text(json.dumps(data), encoding="utf-8")
    except Exception:
        pass


def status() -> dict:
    base = _load()
    return {"established": bool(base), "devices": len(base)}


def reset() -> None:
    try:
        _BASELINE.unlink()
    except Exception:
        pass


def run() -> list[Anomaly]:
    """Establish a baseline (first run with enough data) or score against it."""
    if not settings.baseline_enabled:
        return []
    profiles = analytics.device_profiles()
    if not profiles:
        return []

    baseline = _load()
    if not baseline:
        # Only establish once we've observed enough to be representative.
        stats = analytics.stats()
        if stats.get("total_flows", 0) < settings.baseline_min_flows:
            return []
        _save({ip: {"ports": p["ports"], "remotes": p["remotes"]} for ip, p in profiles.items()})
        return []

    out: list[Anomaly] = []
    for ip, prof in profiles.items():
        base = baseline.get(ip)
        if not base:
            continue  # brand-new device — handled by new-device alerting
        new_ports = sorted(set(prof["ports"]) - set(base.get("ports", [])))
        if new_ports:
            shown = ", ".join(str(p) for p in new_ports[:5])
            out.append(Anomaly(
                key=f"newsvc:{ip}:{new_ports[0]}",
                title=f"{ip} started using new external service(s): port {shown}",
                description=(
                    f"{ip} connected to external port(s) {shown} it never used during the "
                    "learning period. A device suddenly speaking a new protocol can indicate "
                    "new software, misconfiguration, or compromise — verify it's expected."
                ),
                mitre_id="T1071", score=min(100, 40 + len(new_ports) * 5),
            ))
        base_remotes = base.get("remotes", 0)
        if base_remotes and prof["remotes"] > base_remotes * 2 + 15:
            out.append(Anomaly(
                key=f"fanout:{ip}:{prof['remotes'] // 25}",
                title=f"{ip} contacted far more peers than usual ({prof['remotes']} vs ~{base_remotes})",
                description=(
                    f"{ip} is talking to {prof['remotes']} external hosts, well above its "
                    f"baseline of ~{base_remotes}. A sudden fan-out increase can indicate "
                    "scanning, a worm, or a compromised host beaconing widely."
                ),
                mitre_id="T1046", score=min(100, 40 + prof["remotes"] // 10),
            ))
    return out
