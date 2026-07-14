"""Multi-signal device & OS identification.

Because modern phones randomize their MAC address, a single signal (OUI vendor)
is unreliable. This module fuses several weak signals into a best guess with a
confidence score:

  - Gateway match (is this the router?)
  - MAC-OUI vendor
  - Hostname / mDNS keywords
  - Open-port profile
  - TTL (rough OS family hint)
  - mDNS advertised service types
"""
from __future__ import annotations

from dataclasses import dataclass

from .oui import is_randomized_mac, lookup_vendor

# Device type constants (also used as UI icon keys).
ROUTER = "router"
PHONE = "phone"
COMPUTER = "computer"
TV = "tv"
PRINTER = "printer"
IOT = "iot"
GAME = "game_console"
NAS = "nas"
CAMERA = "camera"
UNKNOWN = "unknown"

# Hostname / mDNS keyword -> device type.
_HOSTNAME_HINTS = {
    PHONE: ["iphone", "android", "galaxy", "pixel", "oneplus", "xiaomi", "redmi", "huawei", "mobile"],
    COMPUTER: ["macbook", "imac", "desktop", "laptop", "pc", "windows", "ubuntu", "debian", "fedora", "thinkpad"],
    TV: ["tv", "roku", "firetv", "chromecast", "appletv", "bravia", "shield", "samsungtv", "lgtv", "vizio"],
    PRINTER: ["printer", "hp", "epson", "canon", "brother", "laserjet", "officejet"],
    IOT: ["echo", "alexa", "nest", "hue", "sonos", "smart", "esp", "tuya", "shelly", "wemo"],
    GAME: ["xbox", "playstation", "ps4", "ps5", "nintendo", "switch"],
    NAS: ["nas", "synology", "diskstation", "qnap", "truenas", "freenas"],
    CAMERA: ["camera", "cam", "ipcam", "reolink", "wyze", "ring", "arlo", "hikvision"],
    ROUTER: ["router", "gateway", "openwrt", "asuswrt", "unifi", "eero", "orbi"],
}

# Vendor keyword -> likely device type (weak signal).
_VENDOR_HINTS = {
    PHONE: ["apple", "samsung", "google", "xiaomi", "oneplus", "huawei", "oppo", "vivo"],
    ROUTER: ["tp-link", "netgear", "asus", "d-link", "ubiquiti", "cisco", "mikrotik", "aruba", "ruckus", "zyxel"],
    IOT: ["amazon", "espressif", "tuya", "sonos", "signify", "philips", "belkin", "wemo"],
    PRINTER: ["hewlett", "epson", "canon", "brother", "lexmark", "xerox"],
    NAS: ["synology", "qnap", "western digital"],
    CAMERA: ["hikvision", "dahua", "reolink", "wyze", "amcrest"],
    GAME: ["sony", "microsoft", "nintendo"],
    TV: ["lg electronics", "vizio", "roku", "tcl"],
    COMPUTER: ["intel", "dell", "lenovo", "asustek", "micro-star", "gigabyte", "hon hai", "raspberry"],
}

# Open-port signatures.
_PORT_HINTS = {
    62078: PHONE,        # iPhone sync
    9100: PRINTER,       # raw printing
    515: PRINTER,        # LPD
    631: PRINTER,        # IPP
    8009: TV,            # Chromecast
    32400: NAS,          # Plex media server
    445: COMPUTER,       # SMB (Windows/file server)
    139: COMPUTER,
    3389: COMPUTER,      # RDP
    22: COMPUTER,        # SSH
    554: CAMERA,         # RTSP
}

# mDNS service type -> device type.
_MDNS_HINTS = {
    PHONE: ["_apple-mobdev", "_rdlink"],
    COMPUTER: ["_smb", "_afpovertcp", "_ssh", "_workstation"],
    TV: ["_googlecast", "_airplay", "_raop", "_spotify-connect", "_androidtvremote"],
    PRINTER: ["_ipp", "_printer", "_pdl-datastream"],
    IOT: ["_hap", "_homekit", "_hue", "_sonos"],
}


@dataclass
class Identity:
    device_type: str = UNKNOWN
    os_guess: str = ""
    vendor: str = ""
    confidence: int = 0  # 0-100
    reasons: list[str] | None = None


def _ttl_os(ttl: int | None) -> str:
    if ttl is None:
        return ""
    if ttl >= 200:
        return "Network device"
    if ttl > 64:
        return "Windows"
    if ttl > 32:
        return "Linux / Unix / Android / iOS"
    return ""


def fingerprint(hostname: str = "", open_ports: list[int] | None = None,
                mdns_services: list[str] | None = None, dhcp_os: str = "") -> str:
    """A stable, MAC-independent device signature.

    Combines the signals a device keeps across a MAC change — its hostname, open
    port profile, advertised mDNS service types, and DHCP-derived OS. Returns ''
    when there isn't enough distinctive signal to fingerprint safely (so we never
    correlate two blank devices as "the same"). Used to spot a device that
    randomizes its MAC to evade tracking.
    """
    import hashlib

    hostname = (hostname or "").strip().lower()
    ports = ",".join(str(p) for p in sorted(set(open_ports or [])))
    # mDNS service *types* (e.g. "_airplay._tcp.local." -> "_airplay").
    svc_types = sorted({s.lstrip("_").split(".")[0].split("_")[0] or s
                        for s in (mdns_services or []) if s})
    svcs = ",".join(svc_types)
    dhcp_os = (dhcp_os or "").strip().lower()

    # Require a hostname, or at least two independent signals, to be meaningful.
    strong = bool(hostname)
    weak_count = sum(1 for x in (ports, svcs, dhcp_os) if x)
    if not (strong or weak_count >= 2):
        return ""
    sig = "|".join([hostname, ports, svcs, dhcp_os])
    return hashlib.sha1(sig.encode()).hexdigest()[:16]


def identify(
    *,
    mac: str,
    ip: str,
    hostname: str = "",
    gateway_ip: str = "",
    open_ports: list[int] | None = None,
    ttl: int | None = None,
    mdns_services: list[str] | None = None,
    nmap_os: str = "",
) -> Identity:
    open_ports = open_ports or []
    mdns_services = mdns_services or []
    reasons: list[str] = []
    votes: dict[str, int] = {}

    def vote(dtype: str, weight: int, reason: str) -> None:
        votes[dtype] = votes.get(dtype, 0) + weight
        reasons.append(reason)

    vendor = lookup_vendor(mac) if mac else "Unknown"

    # Strongest signal: is this the gateway?
    if ip and gateway_ip and ip == gateway_ip:
        vote(ROUTER, 100, "IP is the default gateway")

    # Hostname keywords.
    lname = (hostname or "").lower()
    for dtype, kws in _HOSTNAME_HINTS.items():
        if any(kw in lname for kw in kws):
            vote(dtype, 40, f"hostname matches '{dtype}'")

    # Vendor keywords.
    lvendor = vendor.lower()
    for dtype, kws in _VENDOR_HINTS.items():
        if any(kw in lvendor for kw in kws):
            vote(dtype, 20, f"vendor '{vendor}' suggests {dtype}")

    # Open-port signatures.
    for port in open_ports:
        if port in _PORT_HINTS:
            vote(_PORT_HINTS[port], 30, f"open port {port} -> {_PORT_HINTS[port]}")

    # mDNS services.
    for dtype, svcs in _MDNS_HINTS.items():
        if any(any(s in adv for adv in mdns_services) for s in svcs):
            vote(dtype, 35, f"mDNS service suggests {dtype}")

    # Resolve OS guess.
    os_guess = nmap_os or _ttl_os(ttl)
    if "windows" in os_guess.lower():
        vote(COMPUTER, 10, "OS looks like Windows")

    # Pick winner.
    if votes:
        device_type = max(votes, key=votes.get)
        confidence = min(100, votes[device_type])
    else:
        device_type = UNKNOWN
        confidence = 0
        reasons.append("no distinctive signals")

    # Refine OS phrasing for phones.
    if device_type == PHONE and not nmap_os:
        if "apple" in lvendor or "iphone" in lname:
            os_guess = "iOS (likely)"
        elif any(k in lname for k in ["android", "galaxy", "pixel"]):
            os_guess = "Android (likely)"

    if is_randomized_mac(mac):
        reasons.append("MAC is randomized (vendor hidden) — identified via other signals")

    return Identity(
        device_type=device_type,
        os_guess=os_guess,
        vendor=vendor,
        confidence=confidence,
        reasons=reasons,
    )
