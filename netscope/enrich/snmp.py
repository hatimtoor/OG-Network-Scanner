"""Minimal SNMPv2c client (no external dependency).

Queries the standard SNMP "system" group, which printers, access points, NAS
boxes and managed switches expose: description, name, object-id, uptime. Only a
tiny, well-defined slice of SNMP/BER is implemented (GET of scalar OIDs).
"""
from __future__ import annotations

import socket
from dataclasses import dataclass

# Standard system-group OIDs (scalar, ".0" instances).
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"


@dataclass
class SnmpInfo:
    descr: str = ""
    name: str = ""
    object_id: str = ""
    uptime: str = ""
    location: str = ""

    def is_empty(self) -> bool:
        return not any([self.descr, self.name, self.object_id, self.location])

    def to_dict(self) -> dict:
        return self.__dict__


# --------------------------------------------------------------------------- #
# BER encoding
# --------------------------------------------------------------------------- #
def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(value)) + value


def _enc_int(i: int) -> bytes:
    b = i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return _tlv(0x02, b)


def _b128(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    out = bytearray()
    while n:
        out.insert(0, n & 0x7F)
        n >>= 7
    for i in range(len(out) - 1):
        out[i] |= 0x80
    return bytes(out)


def _enc_oid(oid: str) -> bytes:
    arcs = [int(x) for x in oid.split(".")]
    body = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        body += _b128(arc)
    return _tlv(0x06, bytes(body))


def build_get(oids: list[str], community: str = "public",
              request_id: int = 0x0A0B0C0D, pdu_tag: int = 0xA0) -> bytes:
    varbinds = b"".join(_tlv(0x30, _enc_oid(o) + _tlv(0x05, b"")) for o in oids)
    pdu_body = _enc_int(request_id) + _enc_int(0) + _enc_int(0) + _tlv(0x30, varbinds)
    pdu = _tlv(pdu_tag, pdu_body)  # 0xA0 GetRequest, 0xA1 GetNextRequest
    msg = _enc_int(1) + _tlv(0x04, community.encode()) + pdu  # version 1 == v2c
    return _tlv(0x30, msg)


# --------------------------------------------------------------------------- #
# BER decoding
# --------------------------------------------------------------------------- #
def _read_len(data: bytes, i: int) -> tuple[int, int]:
    first = data[i]
    i += 1
    if first < 0x80:
        return first, i
    num = first & 0x7F
    length = int.from_bytes(data[i:i + num], "big")
    return length, i + num


def _parse(data: bytes, i: int = 0, end: int | None = None):
    """Parse TLVs into a nested list of (tag, value_bytes_or_children)."""
    if end is None:
        end = len(data)
    nodes = []
    while i < end:
        tag = data[i]
        length, i = _read_len(data, i + 1)
        value = data[i:i + length]
        if tag & 0x20:  # constructed
            nodes.append((tag, _parse(value, 0, len(value))))
        else:
            nodes.append((tag, value))
        i += length
    return nodes


def _decode_oid(value: bytes) -> str:
    if not value:
        return ""
    first = value[0]
    arcs = [first // 40, first % 40]
    n = 0
    for b in value[1:]:
        n = (n << 7) | (b & 0x7F)
        if not (b & 0x80):
            arcs.append(n)
            n = 0
    return ".".join(str(a) for a in arcs)


def _decode_value(tag: int, value: bytes) -> str:
    if tag == 0x06:
        return _decode_oid(value)
    if tag in (0x02, 0x41, 0x42, 0x43, 0x44):  # int/counter/gauge/timeticks
        return str(int.from_bytes(value, "big")) if value else "0"
    return value.decode("utf-8", "ignore").strip()


def _collect_varbinds(nodes) -> dict[str, str]:
    """Find SEQUENCEs shaped [OID, value] and return {oid: value}."""
    result: dict[str, str] = {}
    for tag, val in nodes:
        if tag & 0x20 and isinstance(val, list):
            if len(val) == 2 and val[0][0] == 0x06:
                oid = _decode_oid(val[0][1])
                vtag, vval = val[1]
                result[oid] = _decode_value(vtag, vval if not isinstance(vval, list) else b"")
            result.update(_collect_varbinds(val))
    return result


# --------------------------------------------------------------------------- #
# Query
# --------------------------------------------------------------------------- #
def _first_varbind(nodes):
    """Return (oid_str, value_tag, value_bytes) of the first OID→value pair."""
    for tag, val in nodes:
        if tag & 0x20 and isinstance(val, list):
            if len(val) == 2 and val[0][0] == 0x06:
                vtag, vval = val[1]
                return _decode_oid(val[0][1]), vtag, (vval if not isinstance(vval, list) else b"")
            r = _first_varbind(val)
            if r[0]:
                return r
    return "", 0, b""


def _send(ip: str, packet: bytes, timeout: float = 2.0) -> bytes:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (ip, 161))
        data, _ = sock.recvfrom(65507)
        return data
    except Exception:
        return b""
    finally:
        try:
            sock.close()
        except Exception:
            pass


def walk(ip: str, base_oid: str, community: str = "public",
         max_rows: int = 128, timeout: float = 2.0) -> list[tuple[str, str]]:
    """SNMP GETNEXT walk of a subtree. Returns [(oid, value), ...]."""
    results: list[tuple[str, str]] = []
    current = base_oid
    for _ in range(max_rows):
        pkt = build_get([current], community, pdu_tag=0xA1)
        data = _send(ip, pkt, timeout)
        if not data:
            break
        try:
            oid, vtag, vval = _first_varbind(_parse(data))
        except Exception:
            break
        if not oid or not oid.startswith(base_oid + "."):
            break  # walked past the subtree
        results.append((oid, _decode_value(vtag, vval)))
        current = oid
    return results


# Interface-table OIDs (32-bit + high-capacity counters).
_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
_IF_IN = "1.3.6.1.2.1.2.2.1.10"
_IF_OUT = "1.3.6.1.2.1.2.2.1.16"
_IF_HCIN = "1.3.6.1.2.1.31.1.1.1.6"
_IF_HCOUT = "1.3.6.1.2.1.31.1.1.1.10"


def _by_index(rows: list[tuple[str, str]]) -> dict[str, str]:
    return {oid.rsplit(".", 1)[-1]: val for oid, val in rows}


def get_interfaces(ip: str, community: str = "public") -> list[dict]:
    """Return per-interface octet counters via an SNMP walk of the ifTable."""
    descr = _by_index(walk(ip, _IF_DESCR, community))
    if not descr:
        return []
    hcin = _by_index(walk(ip, _IF_HCIN, community))
    hcout = _by_index(walk(ip, _IF_HCOUT, community))
    inoct = hcin or _by_index(walk(ip, _IF_IN, community))
    outoct = hcout or _by_index(walk(ip, _IF_OUT, community))
    out = []
    for idx, name in descr.items():
        out.append({
            "index": idx, "descr": name,
            "in_octets": int(inoct.get(idx, "0") or 0),
            "out_octets": int(outoct.get(idx, "0") or 0),
        })
    return out


_last_if: dict[str, dict] = {}


def interface_rates(ip: str, community: str, now: float) -> list[dict]:
    """Per-interface throughput (bytes/sec) between successive polls of a router."""
    ifaces = get_interfaces(ip, community)
    prev = _last_if.get(ip, {})
    cur: dict[str, tuple] = {}
    out: list[dict] = []
    for i in ifaces:
        idx = i["index"]
        cur[idx] = (i["in_octets"], i["out_octets"], now)
        if idx in prev:
            pin, pout, pts = prev[idx]
            dt = now - pts
            if dt > 0:
                out.append({
                    "descr": i["descr"],
                    "in_bps": max(0.0, (i["in_octets"] - pin) / dt),
                    "out_bps": max(0.0, (i["out_octets"] - pout) / dt),
                })
    _last_if[ip] = cur
    return out


def get_system_info(ip: str, community: str = "public", timeout: float = 2.0) -> SnmpInfo:
    oids = [SYS_DESCR, SYS_NAME, SYS_OBJECT_ID, SYS_UPTIME, SYS_LOCATION]
    packet = build_get(oids, community)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (ip, 161))
        data, _ = sock.recvfrom(65507)
    except Exception:
        return SnmpInfo()
    finally:
        try:
            sock.close()
        except Exception:
            pass

    try:
        vb = _collect_varbinds(_parse(data))
    except Exception:
        return SnmpInfo()
    return SnmpInfo(
        descr=vb.get(SYS_DESCR, ""),
        name=vb.get(SYS_NAME, ""),
        object_id=vb.get(SYS_OBJECT_ID, ""),
        uptime=vb.get(SYS_UPTIME, ""),
        location=vb.get(SYS_LOCATION, ""),
    )
