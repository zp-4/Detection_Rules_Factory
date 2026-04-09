"""Tests for mitre_coverage_config load/save helpers."""
import yaml

import services.mitre_coverage_config as mcc
from services.mitre_coverage_config import (
    campaign_by_id,
    load_config,
    save_config,
    scope_technique_ids,
)


def test_load_default_has_scopes_and_campaigns():
    cfg = load_config()
    assert "scopes" in cfg
    assert "campaigns" in cfg
    assert isinstance(cfg["scopes"], dict)
    assert isinstance(cfg["campaigns"], list)


def test_save_roundtrip(monkeypatch, tmp_path):
    p = tmp_path / "mitre_coverage_config.yaml"
    monkeypatch.setattr(mcc, "CONFIG_PATH", str(p))
    cfg = {"scopes": {"test": {"technique_ids": ["T1059"]}}, "campaigns": []}
    save_config(cfg)
    assert p.exists()
    with open(p, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert data["scopes"]["test"]["technique_ids"] == ["T1059"]


def test_campaign_by_id_and_scope_technique_ids():
    cfg = {
        "scopes": {"s1": {"technique_ids": ["T1", "T2"]}},
        "campaigns": [{"id": "c1", "name": "C", "technique_ids": ["T3"]}],
    }
    assert scope_technique_ids(cfg, "s1") == ["T1", "T2"]
    assert scope_technique_ids(cfg, "missing") == []
    assert campaign_by_id(cfg, "c1")["name"] == "C"
    assert campaign_by_id(cfg, "x") is None
