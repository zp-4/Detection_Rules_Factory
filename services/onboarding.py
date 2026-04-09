"""Guided onboarding state and progress helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

_ONBOARDING_PATH = Path("config/onboarding_state.yaml")
_STEPS = ("first_import", "first_audit", "dashboard_seen")


@dataclass(frozen=True)
class OnboardingProgress:
    first_import: bool
    first_audit: bool
    dashboard_seen: bool

    @property
    def completed(self) -> int:
        return int(self.first_import) + int(self.first_audit) + int(self.dashboard_seen)

    @property
    def total(self) -> int:
        return 3


def _load_raw() -> dict[str, Any]:
    if not _ONBOARDING_PATH.exists():
        return {"users": {}}
    with _ONBOARDING_PATH.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        return {"users": {}}
    users = data.get("users", {})
    if not isinstance(users, dict):
        users = {}
    return {"users": users}


def _save_raw(data: dict[str, Any]) -> None:
    _ONBOARDING_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _ONBOARDING_PATH.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=True, allow_unicode=False)


def _state_for_user(data: dict[str, Any], username: str) -> dict[str, bool]:
    row = data["users"].get(username, {})
    if not isinstance(row, dict):
        row = {}
    return {k: bool(row.get(k, False)) for k in _STEPS}


def mark_step(username: str, step: str, done: bool = True) -> bool:
    uname = str(username or "").strip()
    if not uname or step not in _STEPS:
        return False
    data = _load_raw()
    row = _state_for_user(data, uname)
    row[step] = bool(done)
    data["users"][uname] = row
    _save_raw(data)
    return True


def compute_progress(
    *,
    username: str,
    has_import: bool,
    has_audit: bool,
) -> OnboardingProgress:
    uname = str(username or "").strip()
    if not uname:
        return OnboardingProgress(False, False, False)
    data = _load_raw()
    row = _state_for_user(data, uname)
    # Auto-complete by observed data.
    if has_import and not row["first_import"]:
        row["first_import"] = True
    if has_audit and not row["first_audit"]:
        row["first_audit"] = True
    data["users"][uname] = row
    _save_raw(data)
    return OnboardingProgress(
        first_import=row["first_import"],
        first_audit=row["first_audit"],
        dashboard_seen=row["dashboard_seen"],
    )
