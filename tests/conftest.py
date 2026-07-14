"""Pytest fixtures for NetScope.

Env vars are set *before* any netscope import so the config singleton, SQLite
engine, and DuckDB store all point at throwaway temp files — tests never touch a
real database, the network, or a browser.
"""
import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="netscope-test-")
os.environ["NETSCOPE_DB"] = os.path.join(_TMP, "test.db")
os.environ["NETSCOPE_ANALYTICS_DB"] = os.path.join(_TMP, "test.duckdb")
os.environ["NETSCOPE_OPEN_BROWSER"] = "false"
os.environ["NETSCOPE_PASSIVE"] = "false"
os.environ["NETSCOPE_FEEDS"] = "false"

import pytest  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _init_stores():
    from netscope.db import analytics, store
    store.init_db()
    analytics.init()
    yield


@pytest.fixture
def flows():
    """Analytics store with flows/packets cleared for this test."""
    from netscope.db import analytics
    with analytics._lock:
        analytics._conn.execute("DELETE FROM flows")
        analytics._conn.execute("DELETE FROM packets")
    return analytics


@pytest.fixture
def cleandb():
    """SQLite store with events/cases/devices/samples cleared."""
    from sqlmodel import select
    from netscope.db import store
    from netscope.db.models import Case, Device, Event, TrafficSample
    with store.get_session() as s:
        for model in (Event, Case, Device, TrafficSample):
            for row in s.exec(select(model)).all():
                s.delete(row)
        s.commit()
    return store
