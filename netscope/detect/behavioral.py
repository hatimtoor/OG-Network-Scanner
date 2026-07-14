"""Explainable behavioral detections over the flow store.

Per the PRD decision, these are heuristics first (each with a clear "why"); ML
scoring layers on later. Detections are deduplicated by a stable key so the same
condition doesn't re-alert every cycle.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..config import settings
from ..db import analytics
from . import mitre


@dataclass
class Detection:
    key: str                    # stable identity for de-dup
    dtype: str                  # port_scan | vertical_scan | beaconing | new_external
    severity: str               # info | warning | critical
    title: str
    description: str            # the explainable "why"
    mitre_id: str = ""
    entities: dict = field(default_factory=dict)
    score: int = 0

    @property
    def mitre_name(self) -> str:
        return mitre.name(self.mitre_id) if self.mitre_id else ""

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["mitre_name"] = self.mitre_name
        return d


def run_detections() -> list[Detection]:
    """Run all heuristic detections and return the current findings."""
    out: list[Detection] = []

    # Horizontal scan: one process/host contacting many distinct external IPs.
    for r in analytics.scan_candidates(min_remotes=settings.detect_scan_hosts):
        proc = r["process"] or "a process"
        out.append(Detection(
            key=f"hscan:{r['local_ip']}:{r['process']}",
            dtype="port_scan", severity="warning",
            title=f"{proc} contacted {r['remotes']} external hosts",
            description=(
                f"{proc} on {r['local_ip']} connected to {r['remotes']} distinct external "
                "IP addresses. High fan-out can indicate network scanning, a sweeping "
                "worm, or aggressive telemetry."
            ),
            mitre_id="T1046",
            entities={"local_ip": r["local_ip"], "process": r["process"]},
            score=min(100, 40 + r["remotes"]),
        ))

    # Vertical scan: many distinct ports on a single destination.
    for r in analytics.vertical_scan_candidates(min_ports=settings.detect_scan_ports):
        proc = r["process"] or "a process"
        out.append(Detection(
            key=f"vscan:{r['local_ip']}:{r['remote_ip']}:{r['process']}",
            dtype="vertical_scan", severity="warning",
            title=f"{proc} probed {r['ports']} ports on {r['remote_ip']}",
            description=(
                f"{proc} on {r['local_ip']} connected to {r['ports']} different ports on "
                f"{r['remote_ip']} — a classic port-scan pattern."
            ),
            mitre_id="T1046",
            entities={"local_ip": r["local_ip"], "remote_ip": r["remote_ip"],
                      "process": r["process"]},
            score=min(100, 40 + r["ports"]),
        ))

    # Beaconing: steady, long-lived callbacks to one external endpoint.
    for r in analytics.beacon_candidates(
        min_samples=settings.detect_beacon_samples, min_duration_s=600
    ):
        dur_min = max(1, r["duration_s"] // 60)
        proc = r["process"] or "a process"
        out.append(Detection(
            key=f"beacon:{r['local_ip']}:{r['remote_ip']}:{r['remote_port']}",
            dtype="beaconing", severity="warning",
            title=f"Steady callbacks to {r['remote_ip']}:{r['remote_port']}",
            description=(
                f"{proc} maintained a connection to {r['remote_ip']}:{r['remote_port']} "
                f"seen {r['samples']} times over ~{dur_min} min. Regular, persistent "
                "callbacks to a single external endpoint are a common command-and-control "
                "(beaconing) pattern — verify the destination is trusted."
            ),
            mitre_id="T1071.001",
            entities={"local_ip": r["local_ip"], "remote_ip": r["remote_ip"],
                      "remote_port": r["remote_port"], "process": r["process"]},
            score=min(100, 30 + r["samples"]),
        ))

    return out
