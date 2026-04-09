"""Unit tests for feature flag load/save (config path patched)."""
import pytest

import services.feature_flags as ff


def test_load_defaults_when_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(ff, "FLAGS_PATH", str(tmp_path / "nonexistent.yaml"))
    data = ff.load_feature_flags()
    assert data["maintenance_message"] == ""
    assert data["disable_ai_globally"] is False
    assert data["disable_ai_teams"] == []


def test_save_and_roundtrip(tmp_path, monkeypatch):
    path = tmp_path / "feature_flags.yaml"
    monkeypatch.setattr(ff, "FLAGS_PATH", str(path))
    ff.save_feature_flags(
        {"maintenance_message": "Planned downtime", "disable_ai_globally": True}
    )
    loaded = ff.load_feature_flags()
    assert loaded["maintenance_message"] == "Planned downtime"
    assert loaded["disable_ai_globally"] is True


def test_maintenance_message_helper(tmp_path, monkeypatch):
    monkeypatch.setattr(ff, "FLAGS_PATH", str(tmp_path / "f.yaml"))
    ff.save_feature_flags({"maintenance_message": "  hello  ", "disable_ai_globally": False})
    assert ff.maintenance_message() == "hello"


def test_ai_globally_disabled_helper(tmp_path, monkeypatch):
    monkeypatch.setattr(ff, "FLAGS_PATH", str(tmp_path / "f.yaml"))
    ff.save_feature_flags({"maintenance_message": "", "disable_ai_globally": True})
    assert ff.ai_globally_disabled() is True


def test_ai_disabled_for_team_selective(tmp_path, monkeypatch):
    monkeypatch.setattr(ff, "FLAGS_PATH", str(tmp_path / "f.yaml"))
    ff.save_feature_flags(
        {
            "maintenance_message": "",
            "disable_ai_globally": False,
            "disable_ai_teams": ["soc"],
        }
    )
    assert ff.ai_disabled_for_team("soc") is True
    assert ff.ai_disabled_for_team("SOC") is True
    assert ff.ai_disabled_for_team("security") is False
    assert ff.ai_disabled_for_team(None) is False


def test_ai_disabled_for_team_global_wins(tmp_path, monkeypatch):
    monkeypatch.setattr(ff, "FLAGS_PATH", str(tmp_path / "f.yaml"))
    ff.save_feature_flags(
        {"disable_ai_globally": True, "disable_ai_teams": [], "maintenance_message": ""}
    )
    assert ff.ai_disabled_for_team("any") is True
