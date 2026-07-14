"""mitmproxy addon: log one JSON line per HTTP(S) response for NetScope.

Run mitmproxy as a transparent/explicit proxy that your devices trust, with:

    mitmdump -s scripts/mitm-jsonl-addon.py --set netscope_log=C:/path/mitm-flows.jsonl

Then point NetScope at that file:  NETSCOPE_MITM_LOG=C:/path/mitm-flows.jsonl

Decryption happens in mitmproxy (the MITM); NetScope only reads the resulting
log. Only run this on traffic you are authorized to intercept.
"""
import json

from mitmproxy import ctx, http

_LOG = "mitm-flows.jsonl"


def load(loader):
    loader.add_option("netscope_log", str, _LOG, "NetScope JSONL output path")


def response(flow: http.HTTPFlow) -> None:
    global _LOG
    _LOG = ctx.options.netscope_log or _LOG
    try:
        client = flow.client_conn.peername[0] if flow.client_conn.peername else ""
    except Exception:
        client = ""
    rec = {
        "client": client,
        "host": flow.request.host,
        "method": flow.request.method,
        "path": flow.request.path,
        "status": flow.response.status_code if flow.response else 0,
        "user_agent": flow.request.headers.get("user-agent", ""),
        "scheme": flow.request.scheme,
    }
    try:
        with open(_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except Exception:
        pass
