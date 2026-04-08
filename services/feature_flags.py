"""Load/save lightweight feature flags from config/feature_flags.yaml."""
from __future__ import annotations

import os
from typing import Any, Dict

import yaml

FLAGS_PATH = os.path.join("config", "feature_flags.yaml")


def _defaults() -> Dict[str, Any]:
    return {
        "maintenance_message": "",
        "disable_ai_globally": False,
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
    return data


def save_feature_flags(data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(FLAGS_PATH), exist_ok=True)
    merged = _defaults()
    merged.update(data)
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
