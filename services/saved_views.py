"""Saved views for global search filters (per user)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

_SAVED_VIEWS_PATH = Path("config/saved_views.yaml")
_MAX_NAME_LEN = 64
_MAX_QUERY_LEN = 200


@dataclass(frozen=True)
class SavedView:
    name: str
    query: str
    limit_per_type: int


def _normalize_name(name: str) -> str:
    return str(name or "").strip()[:_MAX_NAME_LEN]


def _normalize_query(query: str) -> str:
    return str(query or "").strip()[:_MAX_QUERY_LEN]


def _normalize_limit(v: Any) -> int:
    try:
        n = int(v)
    except Exception:
        n = 20
    return min(50, max(5, n))


def _load_raw() -> dict[str, Any]:
    if not _SAVED_VIEWS_PATH.exists():
        return {"users": {}}
    with _SAVED_VIEWS_PATH.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        return {"users": {}}
    users = data.get("users", {})
    if not isinstance(users, dict):
        users = {}
    return {"users": users}


def _save_raw(data: dict[str, Any]) -> None:
    _SAVED_VIEWS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _SAVED_VIEWS_PATH.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=True, allow_unicode=False)


def list_saved_views(username: str) -> list[SavedView]:
    uname = str(username or "").strip()
    if not uname:
        return []
    data = _load_raw()
    raw = data["users"].get(uname, [])
    if not isinstance(raw, list):
        return []
    out: list[SavedView] = []
    for row in raw:
        if not isinstance(row, dict):
            continue
        name = _normalize_name(str(row.get("name", "")))
        query = _normalize_query(str(row.get("query", "")))
        if not name or not query:
            continue
        out.append(
            SavedView(
                name=name,
                query=query,
                limit_per_type=_normalize_limit(row.get("limit_per_type", 20)),
            )
        )
    return out


def upsert_saved_view(username: str, *, name: str, query: str, limit_per_type: int) -> bool:
    uname = str(username or "").strip()
    nm = _normalize_name(name)
    q = _normalize_query(query)
    lim = _normalize_limit(limit_per_type)
    if not uname or not nm or len(q) < 2:
        return False

    data = _load_raw()
    users = data["users"]
    rows = users.get(uname, [])
    if not isinstance(rows, list):
        rows = []

    updated = False
    for row in rows:
        if isinstance(row, dict) and _normalize_name(str(row.get("name", ""))) == nm:
            row["query"] = q
            row["limit_per_type"] = lim
            updated = True
            break

    if not updated:
        rows.append({"name": nm, "query": q, "limit_per_type": lim})

    # Keep deterministic order for readability.
    rows = sorted(
        [
            {
                "name": _normalize_name(str(r.get("name", ""))),
                "query": _normalize_query(str(r.get("query", ""))),
                "limit_per_type": _normalize_limit(r.get("limit_per_type", 20)),
            }
            for r in rows
            if isinstance(r, dict)
        ],
        key=lambda x: x["name"].casefold(),
    )
    users[uname] = rows
    _save_raw(data)
    return True


def delete_saved_view(username: str, name: str) -> bool:
    uname = str(username or "").strip()
    nm = _normalize_name(name)
    if not uname or not nm:
        return False
    data = _load_raw()
    users = data["users"]
    rows = users.get(uname, [])
    if not isinstance(rows, list):
        return False
    kept = [r for r in rows if not (isinstance(r, dict) and _normalize_name(str(r.get("name", ""))) == nm)]
    if len(kept) == len(rows):
        return False
    users[uname] = kept
    _save_raw(data)
    return True
