"""Runtime configuration for NetScope.

Settings are read from environment variables (optionally loaded from a local
``.env`` file) with sensible defaults so the app runs with zero configuration.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _load_dotenv() -> None:
    """Minimal .env loader (avoids an extra dependency)."""
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


def _get(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _get_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def _get_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


# Common ports probed by the built-in socket scanner (fast, no Nmap needed).
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 515, 631, 993, 995,
    1723, 1883, 1900, 3306, 3389, 5000, 5353, 5900, 8000, 8009, 8080, 8443,
    8883, 9100, 32400, 49152, 62078,
]

# Ports flagged as risky when found open (insecure/legacy/management services).
RISKY_PORTS = {
    21: "FTP (cleartext)",
    23: "Telnet (cleartext, high risk)",
    139: "NetBIOS",
    445: "SMB (file sharing)",
    3389: "RDP (remote desktop)",
    5900: "VNC (remote desktop)",
    1723: "PPTP VPN (weak)",
}


@dataclass
class Settings:
    host: str = field(default_factory=lambda: _get("NETSCOPE_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _get_int("NETSCOPE_PORT", 8000))
    open_browser: bool = field(default_factory=lambda: _get_bool("NETSCOPE_OPEN_BROWSER", True))

    # Network / scanning
    subnet: str = field(default_factory=lambda: _get("NETSCOPE_SUBNET", ""))  # "" = auto-detect
    subnets: str = field(default_factory=lambda: _get("NETSCOPE_SUBNETS", ""))  # comma-separated CIDRs
    scan_all_local: bool = field(default_factory=lambda: _get_bool("NETSCOPE_SCAN_ALL_LOCAL", False))
    scan_interval: int = field(default_factory=lambda: _get_int("NETSCOPE_SCAN_INTERVAL", 120))
    traffic_interval: int = field(default_factory=lambda: _get_int("NETSCOPE_TRAFFIC_INTERVAL", 3))
    ping_timeout_ms: int = field(default_factory=lambda: _get_int("NETSCOPE_PING_TIMEOUT_MS", 600))
    port_scan_enabled: bool = field(default_factory=lambda: _get_bool("NETSCOPE_PORT_SCAN", True))
    use_nmap: bool = field(default_factory=lambda: _get_bool("NETSCOPE_USE_NMAP", True))
    nmap_os_detection: bool = field(default_factory=lambda: _get_bool("NETSCOPE_NMAP_OS", False))
    max_workers: int = field(default_factory=lambda: _get_int("NETSCOPE_MAX_WORKERS", 100))

    # Storage
    db_path: str = field(
        default_factory=lambda: _get(
            "NETSCOPE_DB", str(Path(__file__).resolve().parent.parent / "netscope.db")
        )
    )
    analytics_path: str = field(
        default_factory=lambda: _get(
            "NETSCOPE_ANALYTICS_DB",
            str(Path(__file__).resolve().parent.parent / "netscope-flows.duckdb"),
        )
    )
    flow_record: bool = field(default_factory=lambda: _get_bool("NETSCOPE_FLOW_RECORD", True))
    flow_retention_days: int = field(default_factory=lambda: _get_int("NETSCOPE_FLOW_RETENTION_DAYS", 7))
    event_retention_days: int = field(default_factory=lambda: _get_int("NETSCOPE_EVENT_RETENTION_DAYS", 30))

    # Behavioral detection thresholds
    behavioral_enabled: bool = field(default_factory=lambda: _get_bool("NETSCOPE_BEHAVIORAL", True))
    detect_scan_hosts: int = field(default_factory=lambda: _get_int("NETSCOPE_DETECT_SCAN_HOSTS", 25))
    detect_scan_ports: int = field(default_factory=lambda: _get_int("NETSCOPE_DETECT_SCAN_PORTS", 15))
    detect_beacon_samples: int = field(default_factory=lambda: _get_int("NETSCOPE_DETECT_BEACON_SAMPLES", 50))
    detect_exfil_bytes: int = field(default_factory=lambda: _get_int("NETSCOPE_DETECT_EXFIL_BYTES", 50_000_000))

    # Notifications
    notify_desktop: bool = field(default_factory=lambda: _get_bool("NETSCOPE_NOTIFY_DESKTOP", True))
    smtp_host: str = field(default_factory=lambda: _get("NETSCOPE_SMTP_HOST", ""))
    smtp_port: int = field(default_factory=lambda: _get_int("NETSCOPE_SMTP_PORT", 587))
    smtp_user: str = field(default_factory=lambda: _get("NETSCOPE_SMTP_USER", ""))
    smtp_pass: str = field(default_factory=lambda: _get("NETSCOPE_SMTP_PASS", ""))
    smtp_to: str = field(default_factory=lambda: _get("NETSCOPE_SMTP_TO", ""))
    webhook_url: str = field(default_factory=lambda: _get("NETSCOPE_WEBHOOK_URL", ""))

    # Security (v3) — all optional; features degrade gracefully when unset.
    vt_api_key: str = field(default_factory=lambda: _get("NETSCOPE_VT_API_KEY", ""))
    threat_auto_check: bool = field(default_factory=lambda: _get_bool("NETSCOPE_THREAT_AUTOCHECK", False))
    suricata_eve_path: str = field(default_factory=lambda: _get("NETSCOPE_SURICATA_EVE", ""))
    zeek_log_dir: str = field(default_factory=lambda: _get("NETSCOPE_ZEEK_DIR", ""))
    mitm_log: str = field(default_factory=lambda: _get("NETSCOPE_MITM_LOG", ""))  # mitmproxy JSONL
    snmp_router: str = field(default_factory=lambda: _get("NETSCOPE_SNMP_ROUTER", ""))
    snmp_router_community: str = field(default_factory=lambda: _get("NETSCOPE_SNMP_ROUTER_COMMUNITY", "public"))
    yara_rules_path: str = field(default_factory=lambda: _get("NETSCOPE_YARA_RULES", ""))
    nvd_api_key: str = field(default_factory=lambda: _get("NETSCOPE_NVD_API_KEY", ""))
    cuckoo_url: str = field(default_factory=lambda: _get("NETSCOPE_CUCKOO_URL", ""))
    cuckoo_token: str = field(default_factory=lambda: _get("NETSCOPE_CUCKOO_TOKEN", ""))

    # Deep enrichment
    snmp_community: str = field(default_factory=lambda: _get("NETSCOPE_SNMP_COMMUNITY", "public"))
    passive_enabled: bool = field(default_factory=lambda: _get_bool("NETSCOPE_PASSIVE", True))

    # Full packet capture (R2) — off by default (heavy, needs Npcap + privileges)
    pcap_enabled: bool = field(default_factory=lambda: _get_bool("NETSCOPE_PCAP", False))
    pcap_dir: str = field(
        default_factory=lambda: _get(
            "NETSCOPE_PCAP_DIR", str(Path(__file__).resolve().parent.parent / "pcaps")
        )
    )
    pcap_file_mb: int = field(default_factory=lambda: _get_int("NETSCOPE_PCAP_FILE_MB", 50))
    pcap_max_files: int = field(default_factory=lambda: _get_int("NETSCOPE_PCAP_MAX_FILES", 20))
    pcap_interface: str = field(default_factory=lambda: _get("NETSCOPE_PCAP_INTERFACE", ""))

    # Host agent (R10) + FIM
    host_agent_enabled: bool = field(default_factory=lambda: _get_bool("NETSCOPE_HOST_AGENT", True))
    fim_paths: str = field(default_factory=lambda: _get("NETSCOPE_FIM_PATHS", ""))  # comma-separated
    fim_interval: int = field(default_factory=lambda: _get_int("NETSCOPE_FIM_INTERVAL", 900))

    # Threat-intel feeds (R16) + file extraction (R17)
    feed_urls: str = field(default_factory=lambda: _get(
        "NETSCOPE_FEED_URLS",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt,"
        "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    ))
    feeds_enabled: bool = field(default_factory=lambda: _get_bool("NETSCOPE_FEEDS", True))
    feed_refresh_hours: int = field(default_factory=lambda: _get_int("NETSCOPE_FEED_REFRESH_HOURS", 12))
    misp_url: str = field(default_factory=lambda: _get("NETSCOPE_MISP_URL", ""))
    misp_key: str = field(default_factory=lambda: _get("NETSCOPE_MISP_KEY", ""))
    stix_url: str = field(default_factory=lambda: _get("NETSCOPE_STIX_URL", ""))
    extract_dir: str = field(default_factory=lambda: _get("NETSCOPE_EXTRACT_DIR", ""))

    # Scheduled reports (R21)
    report_schedule_hours: int = field(default_factory=lambda: _get_int("NETSCOPE_REPORT_HOURS", 0))
    report_email: str = field(default_factory=lambda: _get("NETSCOPE_REPORT_EMAIL", ""))

    # Phase C
    anomaly_enabled: bool = field(default_factory=lambda: _get_bool("NETSCOPE_ANOMALY", True))
    baseline_enabled: bool = field(default_factory=lambda: _get_bool("NETSCOPE_BASELINE", True))
    baseline_min_flows: int = field(default_factory=lambda: _get_int("NETSCOPE_BASELINE_MIN_FLOWS", 80))
    honeypot_enabled: bool = field(default_factory=lambda: _get_bool("NETSCOPE_HONEYPOT", False))
    honeypot_ports: str = field(default_factory=lambda: _get("NETSCOPE_HONEYPOT_PORTS", "23,2323,3389,8081"))
    auth_enabled: bool = field(default_factory=lambda: _get_bool("NETSCOPE_AUTH", False))
    auth_password: str = field(default_factory=lambda: _get("NETSCOPE_PASSWORD", ""))
    # Guard against exposing an unauthenticated instance on the network. Binding a
    # non-loopback host with auth off is refused unless this is explicitly set.
    allow_insecure_bind: bool = field(
        default_factory=lambda: _get_bool("NETSCOPE_ALLOW_INSECURE_BIND", False))
    anthropic_key: str = field(default_factory=lambda: _get("NETSCOPE_ANTHROPIC_KEY", ""))
    ai_model: str = field(default_factory=lambda: _get("NETSCOPE_AI_MODEL", "claude-opus-4-8"))


_load_dotenv()
settings = Settings()
