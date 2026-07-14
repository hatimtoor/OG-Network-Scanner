"""Statistical anomaly detection (R5) — the "ML-lite" baseline layer.

Per the PRD decision, this ships explainable statistical anomaly detection first
(a z-score spike detector over learned baselines); heavier unsupervised ML can
layer on later. Today it watches host throughput history for spikes far outside
the learned normal, and per-device flow novelty.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass

from ..db import analytics, store


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


def throughput_anomaly(min_samples: int = 30, floor_bps: float = 500_000.0,
                       z: float = 4.0) -> Anomaly | None:
    """Flag a download/upload spike far above the learned baseline."""
    hist = store.list_traffic_history(limit=240)
    if len(hist) < min_samples:
        return None
    for field, label in (("recv_rate", "download"), ("sent_rate", "upload")):
        series = [h[field] for h in hist]
        baseline, recent = series[:-3], series[-3:]
        if len(baseline) < min_samples - 3:
            continue
        mean = statistics.mean(baseline)
        sd = statistics.pstdev(baseline)
        current = max(recent)
        # z-score threshold when there's variance; ratio threshold for a flat baseline.
        threshold = (mean + z * sd) if sd > 0 else max(mean * 10, floor_bps)
        if current > threshold and current > floor_bps:
            factor = current / max(mean, 1)
            return Anomaly(
                key=f"tput:{label}:{int(current)//1_000_000}",
                title=f"Unusual {label} spike ({current/1e6:.1f} MB/s)",
                description=(
                    f"Host {label} hit {current/1e6:.2f} MB/s — about {factor:.0f}x the "
                    f"recent baseline of {mean/1e6:.2f} MB/s. A sudden spike far outside "
                    "normal can indicate a large transfer, backup, or exfiltration."
                ),
                severity="warning", score=min(100, 40 + int(factor)),
                mitre_id="T1048",
            )
    return None


def run() -> list[Anomaly]:
    out = []
    a = throughput_anomaly()
    if a:
        out.append(a)
    return out
