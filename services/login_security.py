"""Login security controls (rate limiting / temporary lockout)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

_CONFIG_PATH = Path("config/login_security.yaml")
_STATE_PATH = Path("config/login_rate_limit_state.yaml")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass(frozen=True)
class LoginPolicy:
    enabled: bool
    max_failures: int
    window_seconds: int
    lockout_seconds: int


@dataclass(frozen=True)
class LoginDecision:
    allowed: bool
    retry_after_seconds: int
    reason: str


def _default_policy() -> LoginPolicy:
    return LoginPolicy(enabled=True, max_failures=5, window_seconds=900, lockout_seconds=900)


def load_login_policy() -> LoginPolicy:
    p = _default_policy()
    if not _CONFIG_PATH.exists():
        return p
    try:
        with _CONFIG_PATH.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            return p
        return LoginPolicy(
            enabled=bool(data.get("enabled", p.enabled)),
            max_failures=max(1, int(data.get("max_failures", p.max_failures))),
            window_seconds=max(60, int(data.get("window_seconds", p.window_seconds))),
            lockout_seconds=max(60, int(data.get("lockout_seconds", p.lockout_seconds))),
        )
    except Exception:
        return p


def _load_state() -> dict[str, Any]:
    if not _STATE_PATH.exists():
        return {"users": {}}
    try:
        with _STATE_PATH.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            return {"users": {}}
        users = data.get("users", {})
        if not isinstance(users, dict):
            users = {}
        return {"users": users}
    except Exception:
        return {"users": {}}


def _save_state(state: dict[str, Any]) -> None:
    _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _STATE_PATH.open("w", encoding="utf-8") as f:
        yaml.safe_dump(state, f, sort_keys=True, allow_unicode=False)


def _key(username: str) -> str:
    return str(username or "").strip().lower()


def _parse_ts(v: Any) -> datetime | None:
    if not isinstance(v, str) or not v.strip():
        return None
    s = v.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except ValueError:
        return None


def _fmt_ts(dt: datetime) -> str:
    return dt.replace(tzinfo=timezone.utc).isoformat()


def _clean_failures(failures: list[Any], now: datetime, window_seconds: int) -> list[str]:
    out: list[str] = []
    cutoff = now - timedelta(seconds=window_seconds)
    for v in failures:
        dt = _parse_ts(v)
        if dt is None:
            continue
        if dt >= cutoff:
            out.append(_fmt_ts(dt))
    return out


def check_login_allowed(username: str) -> LoginDecision:
    uname = _key(username)
    if not uname:
        return LoginDecision(False, 0, "missing_username")
    pol = load_login_policy()
    if not pol.enabled:
        return LoginDecision(True, 0, "disabled")

    state = _load_state()
    row = state["users"].get(uname, {})
    if not isinstance(row, dict):
        row = {}
    now = _utcnow()
    locked_until = _parse_ts(row.get("locked_until"))
    if locked_until and locked_until > now:
        retry = int((locked_until - now).total_seconds())
        return LoginDecision(False, max(1, retry), "locked")
    return LoginDecision(True, 0, "ok")


def register_failed_attempt(username: str) -> None:
    uname = _key(username)
    if not uname:
        return
    pol = load_login_policy()
    if not pol.enabled:
        return
    now = _utcnow()
    state = _load_state()
    row = state["users"].get(uname, {})
    if not isinstance(row, dict):
        row = {}
    failures = row.get("failures", [])
    if not isinstance(failures, list):
        failures = []
    failures = _clean_failures(failures, now, pol.window_seconds)
    failures.append(_fmt_ts(now))
    row["failures"] = failures
    if len(failures) >= pol.max_failures:
        row["locked_until"] = _fmt_ts(now + timedelta(seconds=pol.lockout_seconds))
        row["failures"] = []
    state["users"][uname] = row
    _save_state(state)


def clear_failures(username: str) -> None:
    uname = _key(username)
    if not uname:
        return
    state = _load_state()
    users = state.get("users", {})
    if not isinstance(users, dict):
        return
    if uname in users:
        users.pop(uname, None)
        _save_state(state)
