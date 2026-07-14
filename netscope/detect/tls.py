"""TLS ClientHello parsing: extract SNI and compute the JA3 fingerprint.

JA3 identifies the client application/library from how it negotiates TLS, even
without decryption. This module parses a raw ClientHello (with or without the
TLS record header). The primary live source of JA3/SNI is Zeek's ssl.log (which
computes JA3 itself); this parser is a dependency-free fallback for captured
handshakes.
"""
from __future__ import annotations

import hashlib
import struct


def _is_grease(v: int) -> bool:
    hi, lo = (v >> 8) & 0xFF, v & 0xFF
    return hi == lo and (hi & 0x0F) == 0x0A


def _u16(data: bytes, i: int) -> int:
    return struct.unpack_from(">H", data, i)[0]


def parse_client_hello(data: bytes) -> dict:
    """Return {version, sni, ja3, ja3_hash} or {} if not a parseable ClientHello."""
    try:
        i = 0
        if data[0] == 0x16:          # TLS record header present
            i = 5
        if data[i] != 0x01:          # handshake type must be client_hello
            return {}
        i += 4                        # msg_type(1) + length(3)
        client_version = _u16(data, i); i += 2
        i += 32                       # random
        sid_len = data[i]; i += 1 + sid_len

        cs_len = _u16(data, i); i += 2
        ciphers = []
        for _ in range(cs_len // 2):
            c = _u16(data, i); i += 2
            if not _is_grease(c):
                ciphers.append(c)

        comp_len = data[i]; i += 1 + comp_len

        sni = ""
        exts, curves, point_formats = [], [], []
        if i + 2 <= len(data):
            ext_total = _u16(data, i); i += 2
            end = i + ext_total
            while i + 4 <= end:
                etype = _u16(data, i); elen = _u16(data, i + 2); i += 4
                body = data[i:i + elen]; i += elen
                if _is_grease(etype):
                    continue
                exts.append(etype)
                if etype == 0x0000 and len(body) >= 5:      # server_name
                    name_len = _u16(body, 3)
                    sni = body[5:5 + name_len].decode("utf-8", "ignore")
                elif etype == 0x000A and len(body) >= 2:     # supported_groups
                    glen = _u16(body, 0)
                    for k in range(2, 2 + glen, 2):
                        g = _u16(body, k)
                        if not _is_grease(g):
                            curves.append(g)
                elif etype == 0x000B and len(body) >= 1:     # ec_point_formats
                    plen = body[0]
                    point_formats = list(body[1:1 + plen])

        ja3 = "{},{},{},{},{}".format(
            client_version,
            "-".join(str(c) for c in ciphers),
            "-".join(str(e) for e in exts),
            "-".join(str(c) for c in curves),
            "-".join(str(p) for p in point_formats),
        )
        return {
            "version": client_version,
            "sni": sni,
            "ja3": ja3,
            "ja3_hash": hashlib.md5(ja3.encode()).hexdigest(),
        }
    except Exception:
        return {}
