"""Tests for rule snapshot text helpers."""
from services.rule_snapshot import mitre_snapshot_text


def test_mitre_snapshot_empty():
    assert mitre_snapshot_text(None) == ""
    assert mitre_snapshot_text({}) == "primary_technique_id: —\ntechnique_ids: —\n"


def test_mitre_snapshot_primary_and_list():
    s = mitre_snapshot_text(
        {"mitre_technique_id": "T1059", "mitre_technique_ids": ["T1059", "T1059.001"]}
    )
    assert "T1059" in s
    assert "T1059.001" in s


def test_mitre_snapshot_non_list_multi():
    s = mitre_snapshot_text({"mitre_technique_id": None, "mitre_technique_ids": {"x": 1}})
    assert "technique_ids:" in s
