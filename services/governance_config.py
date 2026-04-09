"""Governance settings (retention thresholds)."""
from __future__ import annotations

import os
from typing import Any, Dict

import yaml

CONFIG_PATH = os.path.join("config", "governance.yaml")


def _defaults() -> Dict[str, Any]:
    return {"retention_days_after_retired": 90}


def load_governance_config() -> Dict[str, Any]:
    data = _defaults()
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f) or {}
            if isinstance(loaded, dict):
                data.update(loaded)
        except Exception:
            pass
    return data


def save_governance_config(data: Dict[str, Any]) -> None:
    merged = _defaults()
    merged.update(data)
    if "retention_days_after_retired" in merged:
        merged["retention_days_after_retired"] = max(1, int(merged["retention_days_after_retired"]))
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(merged, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
