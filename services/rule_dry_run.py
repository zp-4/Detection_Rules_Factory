"""Lightweight dry-run: overlap between sample event JSON and rule text tokens."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Set


# YAML / Sigma keywords to de-emphasize when tokenizing rule text
_STOP = frozenset(
    """
    title id name description author references date modified level status falsepositives
    logsource product category service definition detection selection condition filter
    fields scope tags annotation fieldsmap
    """.split()
)


def _event_blob(event: Any) -> str:
    try:
        return json.dumps(event, sort_keys=True, default=str).lower()
    except (TypeError, ValueError):
        return str(event).lower()


def _tokens_from_rule(rule_text: str) -> Set[str]:
    if not rule_text:
        return set()
    # split on non-alphanumeric, keep tokens length >= 3
    parts = re.split(r"[^\w]+", rule_text.lower())
    out: Set[str] = set()
    for p in parts:
        if len(p) >= 3 and p not in _STOP and not p.isdigit():
            out.add(p)
    return out


def dry_run_event(rule_text: str, rule_format: str | None, event: Any) -> Dict[str, Any]:
    """
    Heuristic match: fraction of rule tokens that appear in the serialized event.
    Not a full Sigma/Splunk evaluator — useful for quick triage only.
    """
    blob = _event_blob(event)
    tokens = _tokens_from_rule(rule_text or "")
    if not tokens:
        return {
            "match_ratio": 0.0,
            "matched": [],
            "unmatched_sample": [],
            "note": "No extractable tokens from rule text (add field names, EventID, paths, etc.).",
            "rule_format": rule_format or "",
        }

    matched: List[str] = []
    for t in sorted(tokens):
        if t in blob:
            matched.append(t)

    ratio = len(matched) / len(tokens) if tokens else 0.0
    unmatched = [t for t in sorted(tokens) if t not in blob][:15]

    note = (
        "Heuristic only: token overlap between rule text and JSON sample. "
        "Tune the sample or rule to increase overlap for staging tests."
    )
    return {
        "match_ratio": round(ratio, 4),
        "matched": matched[:50],
        "unmatched_sample": unmatched,
        "token_count": len(tokens),
        "note": note,
        "rule_format": rule_format or "",
    }
