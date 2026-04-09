"""Unit tests for mitre_catalog helpers (no ATT&CK bundle required)."""
from types import SimpleNamespace

from services.mitre_catalog import (
    collect_rule_technique_ids,
    collect_covered_technique_ids,
    rule_matches_allowed_techniques,
)


def _rule(mid=None, mids=None):
    return SimpleNamespace(
        mitre_technique_id=mid,
        mitre_technique_ids=mids,
    )


def test_collect_rule_technique_ids_primary():
    s = collect_rule_technique_ids(_rule("T1059", None))
    assert s == {"T1059"}


def test_collect_rule_technique_ids_multi():
    s = collect_rule_technique_ids(_rule("T1059", ["T1059.001", "T1205"]))
    assert "T1059" in s and "T1059.001" in s


def test_collect_covered_union():
    rules = [_rule("T1", None), _rule(None, ["T2"])]
    assert collect_covered_technique_ids(rules) == {"T1", "T2"}


def test_rule_matches_allowed():
    assert rule_matches_allowed_techniques(_rule("T1", None), {"T1", "T2"})
    assert not rule_matches_allowed_techniques(_rule("T9", None), {"T1"})
