"""AI assistant (R24): answer natural-language questions about the network.

When an Anthropic API key is configured (NETSCOPE_ANTHROPIC_KEY) and the
``anthropic`` SDK is installed, questions are answered by Claude over a compact
snapshot of NetScope's data. Without a key, a rule-based fallback handles the
common questions so the feature still works offline.
"""
from __future__ import annotations

from ..config import settings
from ..db import analytics, store

try:
    import anthropic

    _HAVE_SDK = True
except Exception:  # pragma: no cover
    _HAVE_SDK = False


def available() -> bool:
    return bool(settings.anthropic_key) and _HAVE_SDK


def _snapshot() -> str:
    """Compact text summary of current state for the model / fallback."""
    devices = store.list_devices()
    events = store.list_events(limit=40)
    top = analytics.top_talkers(limit=10)
    stats = analytics.stats()

    online = sum(1 for d in devices if d["is_online"])
    types: dict[str, int] = {}
    for d in devices:
        types[d["device_type"]] = types.get(d["device_type"], 0) + 1
    crit = [e for e in events if e["severity"] == "critical"]

    lines = [
        f"Devices: {len(devices)} total, {online} online.",
        "By type: " + ", ".join(f"{k}={v}" for k, v in types.items()),
        f"Flows: {stats.get('total_flows', 0)} total, "
        f"{stats.get('external_flows', 0)} external, "
        f"{stats.get('distinct_remotes', 0)} distinct remote IPs.",
        "Top external talkers: " + ", ".join(f"{t['remote_ip']}({t['flows']})" for t in top[:8]),
        f"Recent alerts ({len(events)}), {len(crit)} critical:",
    ]
    for e in events[:15]:
        lines.append(f"  [{e['severity']}] {e['type']}: {e['message'][:120]}")
    devlines = [
        f"  {d['display_name']} {d['ip']} type={d['device_type']} os={d['os_guess']} "
        f"vendor={d['vendor']} cves={len(d.get('cves', []))}"
        for d in devices[:40]
    ]
    return "\n".join(lines) + "\nDEVICES:\n" + "\n".join(devlines)


_SYSTEM = (
    "You are NetScope's built-in security assistant. Answer the user's question "
    "about THEIR network using ONLY the data provided below. Be concise and "
    "specific, cite device names/IPs, and if the data doesn't contain the answer, "
    "say so plainly. Never invent devices, alerts, or connections."
)


def answer(question: str) -> dict:
    question = (question or "").strip()
    if not question:
        return {"answer": "Ask a question about your network.", "source": "none"}
    if available():
        return _answer_llm(question)
    return _answer_fallback(question)


def _answer_llm(question: str) -> dict:
    try:
        client = anthropic.Anthropic(api_key=settings.anthropic_key)
        resp = client.messages.create(
            model=settings.ai_model,
            max_tokens=1024,
            system=_SYSTEM,
            messages=[{
                "role": "user",
                "content": f"NETWORK DATA:\n{_snapshot()}\n\nQUESTION: {question}",
            }],
        )
        text = "".join(b.text for b in resp.content if b.type == "text").strip()
        return {"answer": text or "(no answer)", "source": "claude", "model": settings.ai_model}
    except Exception as exc:
        fb = _answer_fallback(question)
        fb["answer"] = f"(AI unavailable: {exc}) \n\n" + fb["answer"]
        return fb


def _answer_fallback(question: str) -> dict:
    q = question.lower()
    devices = store.list_devices()
    events = store.list_events(limit=100)

    if any(w in q for w in ("critical", "alert", "wrong", "threat", "attack")):
        crit = [e for e in events if e["severity"] in ("critical", "warning")][:10]
        if not crit:
            return {"answer": "No warning or critical alerts right now.", "source": "rules"}
        body = "\n".join(f"- [{e['severity']}] {e['message']}" for e in crit)
        return {"answer": f"Current alerts:\n{body}", "source": "rules"}

    if any(w in q for w in ("talk", "bandwidth", "top", "traffic", "connect")):
        top = analytics.top_talkers(limit=10)
        if not top:
            return {"answer": "No external flows recorded yet.", "source": "rules"}
        body = "\n".join(f"- {t['remote_ip']}: {t['flows']} flows" for t in top)
        return {"answer": f"Top external destinations:\n{body}", "source": "rules"}

    if any(w in q for w in ("vuln", "cve", "risk", "exposed")):
        vulns = [(d["display_name"], c) for d in devices for c in d.get("cves", [])]
        if not vulns:
            return {"answer": "No known CVEs on inventoried devices. Run a Deep Scan to check more.", "source": "rules"}
        body = "\n".join(f"- {n}: {c['id']} ({c.get('severity')})" for n, c in vulns[:10])
        return {"answer": f"Vulnerabilities found:\n{body}", "source": "rules"}

    if any(w in q for w in ("how many", "device", "count", "what is on", "who is on")):
        online = sum(1 for d in devices if d["is_online"])
        types: dict[str, int] = {}
        for d in devices:
            types[d["device_type"]] = types.get(d["device_type"], 0) + 1
        body = ", ".join(f"{v} {k}" for k, v in types.items())
        return {"answer": f"{len(devices)} devices ({online} online): {body}.", "source": "rules"}

    return {
        "answer": "I can answer about alerts, top talkers/bandwidth, vulnerabilities, and "
                  "device counts. For open-ended questions, set NETSCOPE_ANTHROPIC_KEY and "
                  "`pip install anthropic` to enable the full AI assistant.",
        "source": "rules",
    }
