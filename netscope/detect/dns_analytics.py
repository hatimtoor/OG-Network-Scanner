"""DNS analytics: flag algorithmically-generated domains (DGA) and tunneling.

Pure, testable heuristics over a domain name. Live domains are fed in from the
passive DNS listener (this host's queries) and, when a sensor is present, from
Zeek dns.log for the whole network.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

# Common/benign second-level domains to suppress false positives.
_ALLOW = {
    "google", "gstatic", "googleapis", "youtube", "apple", "icloud", "microsoft",
    "windows", "office", "live", "amazon", "amazonaws", "cloudfront", "akamai",
    "akamaized", "fbcdn", "facebook", "instagram", "whatsapp", "cloudflare", "netflix",
    "spotify", "github", "githubusercontent", "twitter", "twimg", "bing", "office365",
    "digicert", "letsencrypt", "mozilla", "ubuntu", "debian", "steam", "steamstatic",
}
_VOWELS = set("aeiou")


@dataclass
class DomainVerdict:
    domain: str
    category: str = "clean"      # clean | dga | tunneling
    suspicious: bool = False
    score: int = 0
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _second_level(domain: str) -> str:
    parts = domain.strip(".").split(".")
    if len(parts) >= 2:
        return parts[-2]
    return parts[0] if parts else ""


def analyze_domain(domain: str) -> DomainVerdict:
    domain = (domain or "").strip(".").lower()
    v = DomainVerdict(domain=domain)
    if not domain or "." not in domain:
        return v

    labels = domain.split(".")
    sld = _second_level(domain)
    if sld in _ALLOW:
        return v

    # --- Tunneling: long name / many labels / long labels carry data ---
    longest = max((len(l) for l in labels), default=0)
    if len(domain) >= 60 or len(labels) >= 6 or longest >= 40:
        v.category = "tunneling"
        v.suspicious = True
        v.score = min(100, 40 + len(domain) // 2)
        v.reasons.append(
            f"unusually long/deep domain ({len(domain)} chars, {len(labels)} labels, "
            f"longest label {longest}) — characteristic of DNS tunneling/exfiltration"
        )
        return v

    # --- DGA: high-entropy, consonant-heavy, digit-mixed second-level label ---
    if len(sld) >= 8:
        ent = shannon_entropy(sld)
        vowels = sum(1 for c in sld if c in _VOWELS)
        digits = sum(1 for c in sld if c.isdigit())
        vowel_ratio = vowels / len(sld)
        digit_ratio = digits / len(sld)
        signals = []
        score = 0
        if ent >= 3.6:
            score += 35; signals.append(f"high entropy ({ent:.1f})")
        if vowel_ratio < 0.26:
            score += 25; signals.append(f"few vowels ({vowel_ratio:.0%})")
        if digit_ratio >= 0.25:
            score += 20; signals.append(f"digit-heavy ({digit_ratio:.0%})")
        if re.search(r"[bcdfghjklmnpqrstvwxz]{5,}", sld):
            score += 20; signals.append("long consonant run")
        if score >= 55:
            v.category = "dga"
            v.suspicious = True
            v.score = min(100, score)
            v.reasons.append(
                "randomized-looking domain (" + ", ".join(signals) +
                ") — typical of algorithmically-generated malware domains"
            )
    return v
