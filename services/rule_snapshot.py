"""Stable text snapshots of rule fields for version comparison."""
from __future__ import annotations

import json
from typing import Any, Dict, Optional


def mitre_snapshot_text(state: Optional[Dict[str, Any]]) -> str:
    """Human-readable MITRE primary + multi mapping for diffing."""
    if state is None:
        return ""
    if not isinstance(state, dict):
        return ""
    primary = state.get("mitre_technique_id")
    multi = state.get("mitre_technique_ids")
    lines = [f"primary_technique_id: {primary if primary is not None else '—'}"]
    if isinstance(multi, list):
        lines.append("technique_ids: " + ", ".join(str(x) for x in multi))
    elif multi is not None:
        lines.append("technique_ids: " + json.dumps(multi, sort_keys=True))
    else:
        lines.append("technique_ids: —")
    return "\n".join(lines) + "\n"
