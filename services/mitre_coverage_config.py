"""Load/save MITRE scopes and CTI campaigns (YAML)."""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import yaml

CONFIG_PATH = os.path.join("config", "mitre_coverage_config.yaml")


def _defaults() -> Dict[str, Any]:
    return {
        "scopes": {
            "enterprise_full": {
                "name": "Full enterprise matrix",
                "technique_ids": [],
            }
        },
        "campaigns": [],
    }


def load_config() -> Dict[str, Any]:
    data = _defaults()
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f) or {}
            if isinstance(loaded, dict):
                data.update(loaded)
        except Exception:
            pass
    if "scopes" not in data or not isinstance(data["scopes"], dict):
        data["scopes"] = _defaults()["scopes"]
    if "campaigns" not in data or not isinstance(data["campaigns"], list):
        data["campaigns"] = []
    return data


def save_config(data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    merged = _defaults()
    merged.update(data)
    if "scopes" in data:
        merged["scopes"] = data["scopes"]
    if "campaigns" in data:
        merged["campaigns"] = data["campaigns"]
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            merged,
            f,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
        )


def campaign_by_id(cfg: Dict[str, Any], cid: str) -> Optional[Dict[str, Any]]:
    for c in cfg.get("campaigns", []):
        if isinstance(c, dict) and str(c.get("id")) == cid:
            return c
    return None


def scope_technique_ids(cfg: Dict[str, Any], scope_key: str) -> List[str]:
    scopes = cfg.get("scopes") or {}
    entry = scopes.get(scope_key) or {}
    raw = entry.get("technique_ids")
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    return []
