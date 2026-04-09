"""Tests for official MITRE ATT&CK technique URLs."""

from utils.mitre_links import attack_technique_url, technique_links_markdown


def test_attack_technique_url_parent_only():
    assert attack_technique_url("T1059") == "https://attack.mitre.org/techniques/T1059/"
    assert attack_technique_url("  t1190 ") == "https://attack.mitre.org/techniques/T1190/"


def test_attack_technique_url_subtechnique():
    assert attack_technique_url("T1059.001") == "https://attack.mitre.org/techniques/T1059/001/"
    assert attack_technique_url("T1566.001") == "https://attack.mitre.org/techniques/T1566/001/"


def test_attack_technique_url_invalid():
    assert attack_technique_url("") is None
    assert attack_technique_url(None) is None
    assert attack_technique_url("not-a-tech") is None


def test_technique_links_markdown():
    s = technique_links_markdown(["T1059", "T1059.001"])
    assert "[T1059](https://attack.mitre.org/techniques/T1059/)" in s
    assert "T1059.001" in s
    assert "attack.mitre.org" in s
