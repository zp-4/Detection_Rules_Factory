"""Tests for outbound webhooks."""
import pytest

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

    def fake_post(url, json=None, timeout=None):
        called.append((url, json))

        class R:
            status_code = 200

        return R()

    monkeypatch.setattr(wh.requests, "post", fake_post)
    wh.dispatch("audit_completed", {"rule_id": 2})
    assert len(called) == 1
    assert called[0][0] == "http://example.com/hook"
    assert called[0][1]["event"] == "audit_completed"
    assert called[0][1]["data"]["rule_id"] == 2
