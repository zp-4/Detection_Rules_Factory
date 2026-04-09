from __future__ import annotations

from pathlib import Path

from services import onboarding


def test_onboarding_compute_progress_auto_marks_import_audit(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "onboarding_state.yaml"
    monkeypatch.setattr(onboarding, "_ONBOARDING_PATH", target)

    p = onboarding.compute_progress(username="alice", has_import=True, has_audit=False)
    assert p.first_import is True
    assert p.first_audit is False
    assert p.dashboard_seen is False
    assert p.completed == 1

    p2 = onboarding.compute_progress(username="alice", has_import=True, has_audit=True)
    assert p2.first_import is True
    assert p2.first_audit is True
    assert p2.completed == 2


def test_onboarding_mark_step_and_invalid_step(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "onboarding_state.yaml"
    monkeypatch.setattr(onboarding, "_ONBOARDING_PATH", target)

    assert onboarding.mark_step("alice", "dashboard_seen", True) is True
    p = onboarding.compute_progress(username="alice", has_import=False, has_audit=False)
    assert p.dashboard_seen is True

    assert onboarding.mark_step("alice", "invalid", True) is False
