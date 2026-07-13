"""UPnP / SSDP device discovery and description parsing.

Many devices (TVs, printers, routers, media servers, cameras) advertise a UPnP
description document over SSDP that contains the exact friendly name,
manufacturer, model name/number and serial number. This is one of the richest,
zero-hardware sources of device detail on a LAN.
"""
from __future__ import annotations

import socket
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

_SSDP_ADDR = "239.255.255.250"
_SSDP_PORT = 1900
_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {_SSDP_ADDR}:{_SSDP_PORT}\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode()


@dataclass
class UpnpInfo:
    friendly_name: str = ""
    manufacturer: str = ""
    model_name: str = ""
    model_number: str = ""
    serial_number: str = ""
    device_type: str = ""

    def is_empty(self) -> bool:
        return not any(
            [self.friendly_name, self.manufacturer, self.model_name,
             self.model_number, self.serial_number]
        )

    def to_dict(self) -> dict:
        return self.__dict__


def discover_locations(timeout: float = 3.0) -> dict[str, str]:
    """Broadcast an SSDP M-SEARCH; return {ip: description_url}."""
    locations: dict[str, str] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        sock.sendto(_MSEARCH, (_SSDP_ADDR, _SSDP_PORT))
    except Exception:
        return locations

    import time
    end = None
    try:
        while True:
            try:
                data, addr = sock.recvfrom(65507)
            except socket.timeout:
                break
            except Exception:
                break
            ip = addr[0]
            location = _header(data.decode("utf-8", "ignore"), "location")
            if location and ip not in locations:
                locations[ip] = location
    finally:
        sock.close()
    return locations


def _header(text: str, name: str) -> str:
    prefix = name.lower() + ":"
    for line in text.split("\r\n"):
        if line.lower().startswith(prefix):
            return line.split(":", 1)[1].strip()
    return ""


def fetch_description(location: str, timeout: float = 4.0) -> UpnpInfo:
    """Fetch and parse a UPnP description XML document."""
    info = UpnpInfo()
    try:
        import requests

        resp = requests.get(location, timeout=timeout)
        if resp.status_code != 200:
            return info
        xml = resp.text
    except Exception:
        return info

    return parse_description_xml(xml)


def parse_description_xml(xml: str) -> UpnpInfo:
    """Parse a UPnP device-description XML document into UpnpInfo."""
    info = UpnpInfo()
    try:
        root = ET.fromstring(xml)  # namespaces stripped via local-name match below
    except Exception:
        return info

    def find(tag: str) -> str:
        for el in root.iter():
            if el.tag.split("}")[-1].lower() == tag.lower() and el.text:
                return el.text.strip()
        return ""

    info.friendly_name = find("friendlyName")
    info.manufacturer = find("manufacturer")
    info.model_name = find("modelName")
    info.model_number = find("modelNumber")
    info.serial_number = find("serialNumber")
    info.device_type = find("deviceType")
    return info


def describe_all(timeout: float = 3.0) -> dict[str, UpnpInfo]:
    """Discover UPnP devices and return {ip: UpnpInfo} for those that describe."""
    results: dict[str, UpnpInfo] = {}
    for ip, location in discover_locations(timeout).items():
        info = fetch_description(location)
        if not info.is_empty():
            results[ip] = info
    return results


def describe_ip(ip: str, timeout: float = 3.0) -> UpnpInfo:
    """Targeted UPnP description for a single IP (used by deep scan)."""
    for found_ip, location in discover_locations(timeout).items():
        if found_ip == ip:
            return fetch_description(location)
    return UpnpInfo()
