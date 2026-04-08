"""Normalize and build rule.cti_refs for CTI traceability."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def normalize_cti_refs(raw: Any) -> List[Dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        return []
    out: List[Dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        eid = item.get("cti_entry_id")
        if eid is None:
            continue
        try:
            eid_int = int(eid)
        except (TypeError, ValueError):
            continue
        out.append(
            {
                "cti_entry_id": eid_int,
                "note": str(item.get("note") or "").strip(),
                "linked_at": str(item.get("linked_at") or ""),
            }
        )
    return out


def build_cti_refs_from_entry_ids(entry_ids: List[int], note: str = "") -> List[Dict[str, Any]]:
    now = datetime.now(timezone.utc).isoformat()
    seen = set()
    rows = []
    for eid in entry_ids:
        try:
            i = int(eid)
        except (TypeError, ValueError):
            continue
        if i in seen:
            continue
        seen.add(i)
        rows.append({"cti_entry_id": i, "linked_at": now, "note": (note or "").strip()})
    return rows
