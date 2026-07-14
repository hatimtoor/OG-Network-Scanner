"""Tests for netscope/agent/hostfacts.py and netscope/agent/fim.py.

hostfacts: verifies collect() and os_info() return the expected keys.
FIM: builds a baseline over a tmp_path directory, then modifies/deletes
files and asserts the second scan reports the changes.  Uses monkeypatch
to redirect the baseline file and watched paths so tests are isolated.
"""


def test_os_info_contains_required_platform_fields():
    from netscope.agent import hostfacts
    info = hostfacts.os_info()
    for key in ("hostname", "system", "release", "machine", "python"):
        assert key in info
    assert info["system"]  # must be non-empty on any real OS


def test_collect_returns_all_top_level_keys():
    from netscope.agent import hostfacts
    result = hostfacts.collect()
    for key in ("os", "users", "listening_ports", "software_count",
                "software", "hardening"):
        assert key in result
    assert isinstance(result["software_count"], int)
    assert isinstance(result["software"], list)
    assert isinstance(result["listening_ports"], list)


def test_fim_first_scan_establishes_baseline(tmp_path, monkeypatch):
    import netscope.agent.fim as fim_module
    from netscope.config import settings

    baseline_file = tmp_path / "fim_baseline.json"
    monkeypatch.setattr(fim_module, "_BASELINE", baseline_file)
    monkeypatch.setattr(settings, "fim_paths", str(tmp_path))

    (tmp_path / "alpha.txt").write_text("hello")
    (tmp_path / "beta.txt").write_text("world")

    result = fim_module.scan()
    assert result["configured"] is True
    assert result["first_run"] is True
    assert result["watched"] == 2
    # On first run the baseline was empty so all files appear as "added".
    assert len(result["added"]) == 2
    assert result["modified"] == []
    assert result["deleted"] == []


def test_fim_detects_modified_and_deleted_files(tmp_path, monkeypatch):
    import netscope.agent.fim as fim_module
    from netscope.config import settings

    baseline_file = tmp_path / "fim_baseline2.json"
    monkeypatch.setattr(fim_module, "_BASELINE", baseline_file)
    monkeypatch.setattr(settings, "fim_paths", str(tmp_path))

    stable = tmp_path / "stable.txt"
    will_change = tmp_path / "will_change.txt"
    will_delete = tmp_path / "will_delete.txt"

    stable.write_text("unchanged content")
    will_change.write_text("original content")
    will_delete.write_text("temporary content")

    fim_module.scan()  # first run -- establishes baseline, no alerts

    will_change.write_text("completely different content after modification")
    will_delete.unlink()

    result = fim_module.scan()
    assert result["first_run"] is False
    assert any("will_change.txt" in p for p in result["modified"])
    assert any("will_delete.txt" in p for p in result["deleted"])
    assert not any("stable.txt" in p for p in result["modified"])
