"""HTTP User-Agent parsing (the guide's application-layer identification).

A small dependency-free parser that turns a User-Agent string into OS, browser,
and a device-type guess. Fed from Zeek's http.log (whole-network) — a strong
identification signal for the cleartext HTTP that remains on a network.
"""
from __future__ import annotations


def parse(ua: str) -> dict:
    ua = ua or ""
    low = ua.lower()

    # OS
    if "windows nt" in low:
        os_name = "Windows"
    elif "iphone" in low or "ipad" in low or "ios" in low:
        os_name = "iOS"
    elif "mac os x" in low or "macintosh" in low:
        os_name = "macOS"
    elif "android" in low:
        os_name = "Android"
    elif "cros" in low:
        os_name = "ChromeOS"
    elif "linux" in low:
        os_name = "Linux"
    else:
        os_name = ""

    # Browser (order matters — Edge/Opera masquerade as Chrome)
    if "edg" in low:
        browser = "Edge"
    elif "opr" in low or "opera" in low:
        browser = "Opera"
    elif "chrome" in low or "crios" in low:
        browser = "Chrome"
    elif "firefox" in low or "fxios" in low:
        browser = "Firefox"
    elif "safari" in low:
        browser = "Safari"
    elif "curl" in low or "wget" in low or "python" in low:
        browser = ua.split("/")[0]
    else:
        browser = ""

    # Device type
    if "ipad" in low or "tablet" in low:
        device_type = "tablet"
    elif "iphone" in low or ("android" in low and "mobile" in low) or "mobile" in low:
        device_type = "phone"
    elif os_name in ("Windows", "macOS", "Linux", "ChromeOS"):
        device_type = "computer"
    else:
        device_type = ""

    return {"os": os_name, "browser": browser, "device_type": device_type, "raw": ua[:200]}
