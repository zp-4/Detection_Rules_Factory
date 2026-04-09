from __future__ import annotations

from pathlib import Path

from services import saved_views


def test_saved_views_upsert_list_delete(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "saved_views.yaml"
    monkeypatch.setattr(saved_views, "_SAVED_VIEWS_PATH", target)

    ok = saved_views.upsert_saved_view(
        "alice",
        name="Ops backlog",
        query="to_improve",
        limit_per_type=25,
    )
    assert ok is True

    views = saved_views.list_saved_views("alice")
    assert len(views) == 1
    assert views[0].name == "Ops backlog"
    assert views[0].query == "to_improve"
    assert views[0].limit_per_type == 25

    ok2 = saved_views.upsert_saved_view(
        "alice",
        name="Ops backlog",
        query="T1059",
        limit_per_type=999,  # clamped
    )
    assert ok2 is True
    views2 = saved_views.list_saved_views("alice")
    assert len(views2) == 1
    assert views2[0].query == "T1059"
    assert views2[0].limit_per_type == 50

    deleted = saved_views.delete_saved_view("alice", "Ops backlog")
    assert deleted is True
    assert saved_views.list_saved_views("alice") == []


def test_saved_views_reject_invalid_inputs(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "saved_views.yaml"
    monkeypatch.setattr(saved_views, "_SAVED_VIEWS_PATH", target)

    assert saved_views.upsert_saved_view("", name="x", query="abc", limit_per_type=20) is False
    assert saved_views.upsert_saved_view("alice", name="", query="abc", limit_per_type=20) is False
    assert saved_views.upsert_saved_view("alice", name="x", query="a", limit_per_type=20) is False
