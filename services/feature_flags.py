"""Load/save lightweight feature flags from config/feature_flags.yaml."""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

import yaml

FLAGS_PATH = os.path.join("config", "feature_flags.yaml")


def _defaults() -> Dict[str, Any]:
    return {
        "maintenance_message": "",
        "disable_ai_globally": False,
        "disable_ai_teams": [],  # team names where AI is blocked (when not globally disabled)
    }


def load_feature_flags() -> Dict[str, Any]:
    data = _defaults()
    if os.path.exists(FLAGS_PATH):
        try:
            with open(FLAGS_PATH, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f) or {}
            if isinstance(loaded, dict):
                data.update(loaded)
        except Exception:
            pass
    if not isinstance(data.get("disable_ai_teams"), list):
        data["disable_ai_teams"] = []
    return data


def save_feature_flags(data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(FLAGS_PATH), exist_ok=True)
    merged = _defaults()
    merged.update(data)
    if "disable_ai_teams" in merged and merged["disable_ai_teams"] is not None:
        teams = merged["disable_ai_teams"]
        if isinstance(teams, list):
            merged["disable_ai_teams"] = [str(t).strip() for t in teams if str(t).strip()]
        else:
            merged["disable_ai_teams"] = []
    with open(FLAGS_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            merged,
            f,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
        )


def maintenance_message() -> str:
    msg = load_feature_flags().get("maintenance_message") or ""
    return str(msg).strip()


def ai_globally_disabled() -> bool:
    return bool(load_feature_flags().get("disable_ai_globally"))


def _normalized_team_set(teams: Any) -> set:
    if not isinstance(teams, list):
        return set()
    return {str(t).strip().lower() for t in teams if isinstance(t, str) and str(t).strip()}


def ai_disabled_for_team(team: Optional[str]) -> bool:
    """
    True if AI must not run: global switch, or caller's team is in disable_ai_teams.
    When team is None/empty, only the global flag applies.
    """
    flags = load_feature_flags()
    if bool(flags.get("disable_ai_globally")):
        return True
    if not team or not str(team).strip():
        return False
    blocked = _normalized_team_set(flags.get("disable_ai_teams"))
    return str(team).strip().lower() in blocked
