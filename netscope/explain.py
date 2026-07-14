"""Plain-language explanations for alerts.

NetScope surfaces security events that mean nothing to someone who doesn't know
networking. This module turns each event type into a short, jargon-free
explanation anyone who reads English can understand: what it means, and what (if
anything) they should do about it. Attached to every event so the dashboard,
notifications, and reports all speak the same plain language.
"""
from __future__ import annotations

# Friendly, human titles for each event type (shown instead of the raw slug).
_TITLES = {
    "new_device": "New device joined your network",
    "randomized_mac": "A device is hiding its identity",
    "mac_rotation": "A device changed its hardware ID",
    "port_alert": "A device has a risky open door",
    "offline": "A device went offline",
    "online": "A device reconnected",
    "vulnerability": "A device has a known security weakness",
    "port_scan": "A device is scanning many others",
    "vertical_scan": "A device is probing another for weaknesses",
    "beaconing": "A device keeps calling out to the internet",
    "data_exfil": "A device uploaded an unusually large amount of data",
    "anomaly": "Your network traffic changed suddenly",
    "ids_alert": "Your sensor spotted a known attack pattern",
    "threat": "A device contacted a known-dangerous server",
    "threat_feed": "A device contacted a known-dangerous server",
    "dns_anomaly": "A device looked up a suspicious website name",
    "fim": "A watched file was changed",
    "malware_file": "A malicious file crossed your network",
    "honeypot": "Something touched a decoy trap",
    "quarantine": "A device was blocked or unblocked",
    "report": "Scheduled report",
    "info": "For your information",
}

# (meaning, what_to_do) for each event type — deliberately non-technical.
_EXPLANATIONS = {
    "new_device": (
        "A device that has never been seen on your network before just connected.",
        "If you recognize it (a phone, laptop, TV, or gadget you or your family "
        "use), open it and mark it as trusted. If you do NOT recognize it, someone "
        "may be using your Wi-Fi without permission — change your Wi-Fi password.",
    ),
    "randomized_mac": (
        "This device is using a made-up, random hardware ID instead of its real "
        "one. Almost all modern phones do this for privacy, so on its own it is "
        "usually harmless.",
        "If it's your own phone or tablet, there's nothing to do. If you don't "
        "recognize the device, treat it like an unknown guest and keep an eye on it.",
    ),
    "mac_rotation": (
        "A device changed its hardware ID but otherwise looks exactly like one "
        "already on your network. Phones do this normally, but it can also be a "
        "trick to avoid being noticed.",
        "If it matches one of your own devices, you can ignore it. If you can't "
        "place it, watch what it does next.",
    ),
    "port_alert": (
        "This device has an open 'door' (a network port) of a type that is often "
        "risky to leave open, because it can let other people connect to it.",
        "If it's a device you manage, consider turning off that feature or updating "
        "the device. For your own trusted devices this is usually fine to leave.",
    ),
    "offline": (
        "A device that was connected has dropped off the network.",
        "This is normal when something is switched off or leaves Wi-Fi range. No "
        "action needed — unless it's a device that should always be on, like a "
        "security camera.",
    ),
    "online": (
        "A device that was offline has reconnected to your network.",
        "No action needed.",
    ),
    "vulnerability": (
        "This device runs software with a publicly known security weakness that "
        "attackers could use to break in.",
        "Update the device's software or firmware to the newest version. If it's an "
        "old device that can no longer be updated, consider replacing it.",
    ),
    "port_scan": (
        "One device is rapidly trying to reach many different machines. Some apps "
        "do this normally, but it's also exactly what a virus does when it hunts "
        "for other devices to infect.",
        "If this is a device you don't fully trust, disconnect it and run a virus "
        "scan on it.",
    ),
    "vertical_scan": (
        "One device is knocking on many different 'doors' of another single machine "
        "— a common way attackers look for a way in.",
        "If you didn't start a scan yourself, treat the device doing this as "
        "suspicious and investigate it.",
    ),
    "beaconing": (
        "A device is quietly checking in with the same outside server over and over "
        "at steady intervals. Legitimate apps do this, but so does malware talking "
        "to whoever controls it.",
        "If you don't recognize where it's connecting, disconnect the device and "
        "scan it for malware.",
    ),
    "data_exfil": (
        "A device sent an unusually large amount of data out to a server on the "
        "internet. That can be a normal backup — or it can be someone stealing your "
        "files.",
        "Check whether you started a big upload or backup. If not, disconnect the "
        "device right away and investigate.",
    ),
    "anomaly": (
        "Your network's traffic suddenly behaved very differently from its normal "
        "pattern (for example, a huge spike). Sudden changes can be innocent or a "
        "warning sign.",
        "If you weren't doing anything unusually data-heavy, keep an eye out for "
        "other alerts.",
    ),
    "ids_alert": (
        "Your network sensor saw traffic that matches a known attack or threat "
        "pattern from its rule list.",
        "Look at the device involved. If you don't recognize the activity, "
        "disconnect it and scan it.",
    ),
    "threat": (
        "A device on your network communicated with an internet address that is on "
        "a public list of dangerous or malicious servers.",
        "Take this seriously: disconnect the device involved and scan it for "
        "malware.",
    ),
    "threat_feed": (
        "A device on your network communicated with an internet address that is on "
        "a public list of dangerous or malicious servers.",
        "Take this seriously: disconnect the device involved and scan it for "
        "malware.",
    ),
    "dns_anomaly": (
        "A device looked up a website name that appears to be auto-generated or "
        "used to sneak data out — a technique commonly used by malware.",
        "If you don't recognize the device or what it was doing, disconnect it and "
        "scan it.",
    ),
    "fim": (
        "An important file that NetScope was watching was changed or deleted. If you "
        "didn't do it, something else did.",
        "If you made the change, ignore this. Otherwise it can be a sign of "
        "tampering — investigate what changed the file.",
    ),
    "malware_file": (
        "A file that was transferred over your network was identified as malicious "
        "(a virus or malware).",
        "Do not open the file. Find the device that downloaded it and scan it.",
    ),
    "honeypot": (
        "A device connected to a fake 'trap' service NetScope set up on purpose. "
        "Normal devices have no reason to touch it, so this strongly suggests "
        "something is snooping around your network.",
        "Identify the device that hit the trap — it's behaving suspiciously.",
    ),
    "quarantine": (
        "A device was blocked from (or allowed back onto) your network.",
        "No action needed — this is a record of an action that was taken.",
    ),
    "report": (
        "A scheduled summary of your network was generated.",
        "No action needed.",
    ),
}

_SEVERITY_LABELS = {
    "info": "For your information",
    "warning": "Worth a look",
    "critical": "Needs your attention",
}

_DEFAULT = (
    "NetScope recorded an event on your network.",
    "No specific action is needed. If you see many of these, look for a pattern.",
)


def friendly_title(event_type: str) -> str:
    return _TITLES.get(event_type, event_type.replace("_", " ").capitalize())


def severity_label(severity: str) -> str:
    return _SEVERITY_LABELS.get(severity, "For your information")


def explain(event_type: str, severity: str = "info") -> dict:
    """Return a plain-language explanation for an event type."""
    meaning, action = _EXPLANATIONS.get(event_type, _DEFAULT)
    return {
        "friendly_title": friendly_title(event_type),
        "severity_label": severity_label(severity),
        "meaning": meaning,
        "action": action,
    }


def notify_body(event_type: str, detail: str, severity: str = "info") -> str:
    """A plain-language notification body: the specifics, then what it means/to do."""
    meaning, action = _EXPLANATIONS.get(event_type, _DEFAULT)
    return f"{detail}\n\nWhat it means: {meaning}\nWhat to do: {action}"
