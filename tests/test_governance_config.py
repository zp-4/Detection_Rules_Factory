import services.governance_config as g


def test_load_defaults(monkeypatch, tmp_path):
    monkeypatch.setattr(g, "CONFIG_PATH", str(tmp_path / "g.yaml"))
    d = g.load_governance_config()
    assert d.get("retention_days_after_retired") == 90
