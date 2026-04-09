"""Tests for outbound webhooks."""
import services.webhooks as wh


def test_dispatch_noop_when_disabled(tmp_path, monkeypatch):
    monkeypatch.setattr(wh, "WEBHOOKS_PATH", str(tmp_path / "w.yaml"))
    (tmp_path / "w.yaml").write_text("enabled: false\nendpoints: []\n", encoding="utf-8")
    called = []

    def fake_post(*a, **k):
        called.append(1)

    monkeypatch.setattr(wh.requests, "post", fake_post)
    wh.dispatch("audit_completed", {"rule_id": 1})
    assert called == []


def test_dispatch_posts_when_enabled(tmp_path, monkeypatch):
    monkeypatch.setattr(wh, "WEBHOOKS_PATH", str(tmp_path / "w.yaml"))
    (tmp_path / "w.yaml").write_text(
        "enabled: true\n"
        "endpoints:\n"
        "  - url: http://example.com/hook\n"
        "    events: [audit_completed]\n",
        encoding="utf-8",
    )
    called = []

    def fake_post(url, data=None, headers=None, timeout=None):
        called.append((url, data, headers, timeout))

        class R:
            status_code = 200

        return R()

    monkeypatch.setattr(wh.requests, "post", fake_post)
    wh.dispatch("audit_completed", {"rule_id": 2})
    assert len(called) == 1
    assert called[0][0] == "http://example.com/hook"
    body = called[0][1].decode("utf-8")
    assert '"event":"audit_completed"' in body
    assert '"rule_id":2' in body
    assert called[0][2]["X-DRF-Event"] == "audit_completed"
    assert called[0][3] == 8.0


def test_dispatch_retries_on_server_error(tmp_path, monkeypatch):
    monkeypatch.setattr(wh, "WEBHOOKS_PATH", str(tmp_path / "w.yaml"))
    (tmp_path / "w.yaml").write_text(
        "enabled: true\n"
        "retries: 2\n"
        "retry_backoff_seconds: 0\n"
        "endpoints:\n"
        "  - url: http://example.com/hook\n"
        "    events: [audit_completed]\n",
        encoding="utf-8",
    )
    calls = {"n": 0}

    def fake_post(url, data=None, headers=None, timeout=None):
        calls["n"] += 1

        class R:
            status_code = 500 if calls["n"] < 3 else 200

        return R()

    monkeypatch.setattr(wh.requests, "post", fake_post)
    wh.dispatch("audit_completed", {"rule_id": 3})
    assert calls["n"] == 3


def test_dispatch_adds_hmac_signature_when_secret_present(tmp_path, monkeypatch):
    monkeypatch.setattr(wh, "WEBHOOKS_PATH", str(tmp_path / "w.yaml"))
    (tmp_path / "w.yaml").write_text(
        "enabled: true\n"
        "signing_secret_env: DRF_WEBHOOK_SECRET\n"
        "endpoints:\n"
        "  - url: http://example.com/hook\n"
        "    events: [audit_completed]\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("DRF_WEBHOOK_SECRET", "top-secret")
    captured = {}

    def fake_post(url, data=None, headers=None, timeout=None):
        captured["headers"] = headers or {}

        class R:
            status_code = 200

        return R()

    monkeypatch.setattr(wh.requests, "post", fake_post)
    wh.dispatch("audit_completed", {"rule_id": 4})
    assert "X-DRF-Signature" in captured["headers"]
    assert len(captured["headers"]["X-DRF-Signature"]) == 64
