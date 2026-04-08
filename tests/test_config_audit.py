"""Tests for config audit repository."""
import pytest
from db.session import SessionLocal, init_db
from db.repo import ConfigAuditRepository


@pytest.fixture
def db():
    init_db()
    session = SessionLocal()
    yield session
    session.close()


def test_config_audit_append_and_list(db):
    ConfigAuditRepository.append(
        db,
        "tester",
        "platform",
        "save_feature_flags",
        {"disable_ai_globally": False},
    )
    rows = ConfigAuditRepository.list_recent(db, limit=10)
    assert len(rows) >= 1
    assert rows[0].actor_username == "tester"
    assert rows[0].category == "platform"
    assert rows[0].detail.get("disable_ai_globally") is False
