"""Governed business tags for the rules catalogue (YAML config)."""
from __future__ import annotations

import os
from typing import Any, Dict, List, Tuple

import yaml

TAGS_PATH = os.path.join("config", "business_tags.yaml")


def _defaults() -> Dict[str, Any]:
    return {
        "allowed_tags": [],
        "enforce_catalogue_tags": False,
    }


def load_business_tags() -> Dict[str, Any]:
    data = _defaults()
    if os.path.exists(TAGS_PATH):
        try:
            with open(TAGS_PATH, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f) or {}
            if isinstance(loaded, dict):
                data.update(loaded)
        except Exception:
            pass
    if not isinstance(data.get("allowed_tags"), list):
        data["allowed_tags"] = []
    return data


def save_business_tags(data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(TAGS_PATH), exist_ok=True)
    merged = _defaults()
    merged.update(data)
    if isinstance(merged.get("allowed_tags"), list):
        merged["allowed_tags"] = [str(x).strip() for x in merged["allowed_tags"] if str(x).strip()]
    merged["enforce_catalogue_tags"] = bool(merged.get("enforce_catalogue_tags"))
    with open(TAGS_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            merged,
            f,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
        )


def validate_rule_tags(tags: List[str], cfg: Dict[str, Any] | None = None) -> Tuple[bool, str]:
    """
    If enforce_catalogue_tags and allowed_tags non-empty, every tag must be in allowed_tags.
    Returns (ok, error_message).
    """
    cfg = cfg or load_business_tags()
    if not cfg.get("enforce_catalogue_tags"):
        return True, ""
    allowed = {str(x).strip() for x in (cfg.get("allowed_tags") or []) if str(x).strip()}
    if not allowed:
        return True, ""
    for t in tags:
        ts = str(t).strip()
        if ts and ts not in allowed:
            return False, f"Tag not allowed by governance: {ts}. Allowed: {sorted(allowed)}"
    return True, ""
