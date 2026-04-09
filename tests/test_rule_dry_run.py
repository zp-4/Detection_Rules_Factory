import json

from services.rule_dry_run import dry_run_event


def test_dry_run_overlap():
    rule = "selection:\n  CommandLine|contains: powershell\ncondition: selection"
    ev = {"CommandLine": "powershell.exe -nop"}
    r = dry_run_event(rule, "sigma", ev)
    assert r["match_ratio"] > 0
    assert "powershell" in r["matched"]


def test_dry_run_no_tokens():
    r = dry_run_event("a", "sigma", {})
    assert r["match_ratio"] == 0.0
    assert "No extractable" in r["note"]
