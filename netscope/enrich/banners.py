"""Service banner, HTTP header, and TLS certificate fingerprinting.

Connects to a device's open ports and reads what the services reveal about
themselves: SSH/FTP/SMTP greeting banners, HTTP ``Server`` headers and page
titles, and TLS certificate common names. This turns "port 22 open" into
"OpenSSH 8.9 on Ubuntu".
"""
from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass, field

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_BANNER_PORTS = {21, 22, 23, 25, 110, 143, 587, 3306}
_HTTP_PORTS = {80, 8000, 8080, 5000, 9000}
_HTTPS_PORTS = {443, 8443, 8843}


@dataclass
class PortDetail:
    port: int
    banner: str = ""
    http_server: str = ""
    http_title: str = ""
    tls_cn: str = ""
    tls_issuer: str = ""

    def to_dict(self) -> dict:
        return self.__dict__


@dataclass
class BannerResult:
    ports: list[PortDetail] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)  # e.g. "nginx/1.24", "OpenSSH_8.9"


def grab_banner(ip: str, port: int, timeout: float = 3.0) -> str:
    """Read a plaintext service greeting (SSH/FTP/SMTP/etc.)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256)
            return data.decode("utf-8", "ignore").strip()
    except Exception:
        return ""


def http_info(ip: str, port: int, tls: bool = False, timeout: float = 4.0) -> tuple[str, str]:
    """Return (server_header, page_title) from an HTTP(S) endpoint."""
    try:
        import requests

        scheme = "https" if tls else "http"
        resp = requests.get(
            f"{scheme}://{ip}:{port}/", timeout=timeout, verify=False,
            allow_redirects=True,
        )
        server = resp.headers.get("Server", "")
        title = ""
        m = _TITLE_RE.search(resp.text or "")
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
        return server, title
    except Exception:
        return "", ""


def tls_info(ip: str, port: int, timeout: float = 4.0) -> tuple[str, str]:
    """Return (cert_common_name, issuer) from a TLS endpoint (best effort)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except Exception:
        return "", ""
    if not der:
        return "", ""
    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(der)
        cn = ""
        issuer = ""
        try:
            cn = cert.subject.rfc4514_string()
        except Exception:
            pass
        try:
            issuer = cert.issuer.rfc4514_string()
        except Exception:
            pass
        return cn[:120], issuer[:120]
    except Exception:
        # cryptography not installed: we still confirmed TLS is present.
        return "TLS certificate present", ""


def probe_ports(ip: str, open_ports: list[int]) -> BannerResult:
    result = BannerResult()
    for port in open_ports:
        detail = PortDetail(port=port)
        if port in _HTTP_PORTS:
            detail.http_server, detail.http_title = http_info(ip, port, tls=False)
        elif port in _HTTPS_PORTS:
            detail.http_server, detail.http_title = http_info(ip, port, tls=True)
            detail.tls_cn, detail.tls_issuer = tls_info(ip, port)
        elif port in _BANNER_PORTS:
            detail.banner = grab_banner(ip, port)

        for val in (detail.banner, detail.http_server):
            if val:
                result.hints.append(val)
        if detail.banner or detail.http_server or detail.http_title or detail.tls_cn:
            result.ports.append(detail)
    return result
