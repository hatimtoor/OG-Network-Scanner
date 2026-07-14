"""API surface tests.

httpx (Starlette TestClient) is not a runtime dependency, so instead of an HTTP
client we assert the routing table and call the endpoint coroutines directly via
asyncio.run — exercising the real handler code without a live server.
"""
import asyncio

from netscope.api import server


EXPECTED_ROUTES = {
    "/api/status", "/api/devices", "/api/dashboard", "/api/auth", "/api/events",
    "/api/ai/status", "/api/ai", "/api/cases", "/api/scan", "/api/traffic",
    "/api/flows", "/api/flows/top", "/api/flows/stats", "/api/login", "/api/logout",
    "/api/response/quarantine", "/api/response/quarantined", "/api/playbooks",
}


def test_expected_routes_registered():
    paths = {r.path for r in server.app.routes}
    missing = EXPECTED_ROUTES - paths
    assert not missing, f"missing routes: {sorted(missing)}"


def test_status_endpoint():
    data = asyncio.run(server.get_status())
    assert data["app"] and data["version"]
    assert "scanning" in data and "scan_interval" in data


def test_auth_status_endpoint():
    data = asyncio.run(server.auth_status())
    assert "enabled" in data


def test_devices_endpoint_returns_list(cleandb):
    assert isinstance(asyncio.run(server.get_devices()), list)


def test_dashboard_endpoint(cleandb):
    data = asyncio.run(server.get_dashboard())
    assert "flows" in data and "throughput" in data


def test_ai_status_endpoint():
    data = asyncio.run(server.ai_status())
    assert "available" in data or "enabled" in data


def test_flow_stats_endpoint(flows):
    data = asyncio.run(server.get_flow_stats())
    assert "available" in data
