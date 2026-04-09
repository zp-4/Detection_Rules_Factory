from __future__ import annotations

from pathlib import Path

from services import login_security as ls


def test_login_rate_limit_locks_after_threshold(monkeypatch, tmp_path: Path) -> None:
    cfg = tmp_path / "login_security.yaml"
    state = tmp_path / "login_rate_limit_state.yaml"
    cfg.write_text(
        "enabled: true\nmax_failures: 3\nwindow_seconds: 3600\nlockout_seconds: 600\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(ls, "_CONFIG_PATH", cfg)
    monkeypatch.setattr(ls, "_STATE_PATH", state)

    assert ls.check_login_allowed("alice").allowed is True
    ls.register_failed_attempt("alice")
    ls.register_failed_attempt("alice")
    assert ls.check_login_allowed("alice").allowed is True
    ls.register_failed_attempt("alice")
    d = ls.check_login_allowed("alice")
    assert d.allowed is False
    assert d.retry_after_seconds > 0


def test_login_rate_limit_cleared_after_success(monkeypatch, tmp_path: Path) -> None:
    cfg = tmp_path / "login_security.yaml"
    state = tmp_path / "login_rate_limit_state.yaml"
    cfg.write_text(
        "enabled: true\nmax_failures: 2\nwindow_seconds: 3600\nlockout_seconds: 600\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(ls, "_CONFIG_PATH", cfg)
    monkeypatch.setattr(ls, "_STATE_PATH", state)

    ls.register_failed_attempt("alice")
    ls.clear_failures("alice")
    assert ls.check_login_allowed("alice").allowed is True
