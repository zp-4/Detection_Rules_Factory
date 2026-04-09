"""Tests for NL rule draft assistant (quota + service)."""
import uuid

import pytest

from db.session import SessionLocal, init_db
from services.quota import set_quota_limit
from services.rule_draft_assistant import run_rule_draft_assistant
@pytest.fixture
def db():
    init_db()
    s = SessionLocal()
    yield s
    s.close()


def test_assistant_requires_length(db, monkeypatch):
    monkeypatch.setattr("services.rule_draft_assistant.get_current_user", lambda: "admin")
    monkeypatch.setattr("services.rule_draft_assistant.get_user_team", lambda u: "security")

    class E:
        def draft_rule_from_natural_language(self, *a, **k):
            return {}

    r = run_rule_draft_assistant(db, E(), "short")  # noqa: type
    assert "error" in r


def test_assistant_consumes_quota_on_success(db, monkeypatch):
    team = f"t_{uuid.uuid4().hex[:8]}"
    monkeypatch.setattr("services.rule_draft_assistant.get_current_user", lambda: "admin")
    monkeypatch.setattr("services.rule_draft_assistant.get_user_team", lambda u: team)

    set_quota_limit(db, team, 100)

    class E:
        def draft_rule_from_natural_language(self, *a, **k):
            return {
                "not_applicable": False,
                "rule_name": "Unit test draft",
                "rule_text": "title: u\nid: x\ndetection:\n  condition: selection\n",
                "fp_checklist": ["a", "b", "c"],
                "mitre_technique_id": "T1059",
                "summary": "ok",
            }

    r = run_rule_draft_assistant(
        db,
        E(),
        "Detect suspicious PowerShell with network and file writes on Windows.",
        preferred_platform="Windows",
        preferred_format="sigma",
    )
    assert r.get("error") is None
    assert r.get("rule_name") == "Unit test draft"

    from services.quota import check_quota

    _, used, _ = check_quota(db, team)
    assert used >= 1
