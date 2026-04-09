from services.rule_playbook import (
    normalize_playbook,
    playbook_from_form,
    format_playbook_for_diff,
)


def test_normalize_empty():
    assert normalize_playbook(None)["false_positive"] == ""


def test_playbook_from_form_contacts():
    pb = playbook_from_form(
        "fp note",
        "val steps",
        "esc to L3",
        '[{"name":"SOC","role":"L2","channel":"#soc"}]',
    )
    assert pb["false_positive"] == "fp note"
    assert len(pb["contacts"]) == 1
    assert pb["contacts"][0]["name"] == "SOC"


def test_format_for_diff():
    s = format_playbook_for_diff({"false_positive": "x", "validation": "", "escalation": "", "contacts": []})
    assert "false_positive" in s and "x" in s
