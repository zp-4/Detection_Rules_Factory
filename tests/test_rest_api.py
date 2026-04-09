"""Tests for optional FastAPI REST layer."""
import pytest
import yaml
from fastapi.testclient import TestClient

from db.session import init_db


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    init_db()
    cfg = {"enabled": True, "tokens": [{"name": "test", "token": "test-token-xyz"}]}
    p = tmp_path / "rest_api.yaml"
    p.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    import rest_api

    monkeypatch.setattr(rest_api, "CONFIG_PATH", str(p))
    return TestClient(rest_api.app)


def test_health_no_auth(api_client):
    r = api_client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_rules_requires_bearer(api_client):
    r = api_client.get("/api/v1/rules")
    assert r.status_code == 401


def test_rules_forbidden_bad_token(api_client):
    r = api_client.get(
        "/api/v1/rules",
        headers={"Authorization": "Bearer wrong"},
    )
    assert r.status_code == 403


def test_rules_ok_with_token(api_client):
    r = api_client.get(
        "/api/v1/rules",
        headers={"Authorization": "Bearer test-token-xyz"},
    )
    assert r.status_code == 200
    assert isinstance(r.json(), list)
