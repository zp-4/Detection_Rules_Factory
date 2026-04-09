from __future__ import annotations

from services import security_posture as sp


def test_security_findings_non_prod(monkeypatch) -> None:
    monkeypatch.setenv("APP_ENV", "dev")
    assert sp.security_findings() == []


def test_security_findings_prod_detects_weak_accounts(monkeypatch) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setattr(
        sp,
        "load_rbac_config",
        lambda: {
            "users": {
                "admin": {"team": "security", "role": "admin"},
                "reader": {"team": "soc", "role": "reader", "password_hash": "pbkdf2_sha256$..."},
            }
        },
    )
    monkeypatch.setattr(sp, "load_webhook_config", lambda: {"enabled": False, "endpoints": []})
    monkeypatch.setattr(sp, "DATABASE_URL", "sqlite:///./usecase_factory.db")

    findings = sp.security_findings()
    assert any("SQLite" in f for f in findings)
    assert any("password_hash" in f for f in findings)
