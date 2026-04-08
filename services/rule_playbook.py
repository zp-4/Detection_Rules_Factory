"""Structured playbook per rule (FP, validation, escalation, contacts)."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


def default_playbook() -> Dict[str, Any]:
    return {
        "false_positive": "",
        "validation": "",
        "escalation": "",
        "contacts": [],
    }


def normalize_playbook(raw: Optional[Any]) -> Dict[str, Any]:
    """Return a safe playbook dict from DB JSON or None."""
    base = default_playbook()
    if raw is None:
        return base
    if not isinstance(raw, dict):
        return base
    out = dict(base)
    for k in ("false_positive", "validation", "escalation"):
        v = raw.get(k)
        out[k] = str(v).strip() if v is not None else ""
    contacts = raw.get("contacts")
    if isinstance(contacts, list):
        cleaned: List[Dict[str, str]] = []
        for c in contacts:
            if not isinstance(c, dict):
                continue
            cleaned.append(
                {
                    "name": str(c.get("name", "")).strip(),
                    "role": str(c.get("role", "")).strip(),
                    "channel": str(c.get("channel", "")).strip(),
                }
            )
        out["contacts"] = cleaned
    return out


def playbook_from_form(
    false_positive: str,
    validation: str,
    escalation: str,
    contacts_json: str,
) -> Dict[str, Any]:
    """Build playbook from form fields; contacts_json is a JSON array of objects."""
    pb = normalize_playbook({})
    pb["false_positive"] = (false_positive or "").strip()
    pb["validation"] = (validation or "").strip()
    pb["escalation"] = (escalation or "").strip()
    pb["contacts"] = []
    raw = (contacts_json or "").strip()
    if raw:
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                pb["contacts"] = normalize_playbook({"contacts": data})["contacts"]
        except json.JSONDecodeError:
            pass
    return pb


def format_playbook_for_diff(pb: Optional[Dict[str, Any]]) -> str:
    """Stable text for changelog / diff."""
    n = normalize_playbook(pb)
    lines = [
        f"false_positive:\n{n['false_positive']}",
        f"validation:\n{n['validation']}",
        f"escalation:\n{n['escalation']}",
        "contacts:",
    ]
    for c in n["contacts"]:
        lines.append(
            f"  - name: {c.get('name', '')} | role: {c.get('role', '')} | channel: {c.get('channel', '')}"
        )
    if not n["contacts"]:
        lines.append("  —")
    return "\n".join(lines) + "\n"
