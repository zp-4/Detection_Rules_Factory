"""Validate and normalize external ticket references (Jira, ServiceNow, Linear, etc.)."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

ALLOWED_SYSTEMS = frozenset({"jira", "servicenow", "linear", "other"})


def parse_ticket_refs_json(raw: str) -> Optional[List[Dict[str, Any]]]:
    """
    Parse JSON array of objects with keys: system (required), key (optional), url (optional).
    Returns None if invalid.
    """
    if not raw or not str(raw).strip():
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, list):
        return None
    out: List[Dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            return None
        system = str(item.get("system", "")).strip().lower()
        if system not in ALLOWED_SYSTEMS:
            return None
        entry: Dict[str, Any] = {"system": system}
        key = item.get("key")
        if key is not None:
            entry["key"] = str(key).strip()[:255]
        url = item.get("url")
        if url is not None and str(url).strip():
            u = str(url).strip()[:2000]
            if not re.match(r"^https?://", u, re.I):
                return None
            entry["url"] = u
        out.append(entry)
    return out


def ticket_refs_to_display_lines(refs: Any) -> List[str]:
    """Short lines for catalogue cards."""
    if not refs or not isinstance(refs, list):
        return []
    lines = []
    for r in refs:
        if not isinstance(r, dict):
            continue
        sys = r.get("system", "?")
        key = r.get("key") or ""
        url = r.get("url") or ""
        if url:
            lines.append(f"[{sys}] {key or url}".strip())
        elif key:
            lines.append(f"[{sys}] {key}")
    return lines
