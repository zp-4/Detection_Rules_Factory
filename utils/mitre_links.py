"""Official MITRE ATT&CK technique URLs (explainability / traceability)."""

from __future__ import annotations

import re
from typing import Any, Iterable, List, Optional

_BASE = "https://attack.mitre.org/techniques"
# Enterprise technique: T1234 or T1234.056 (parent.sub)
_RE_TECH = re.compile(r"^(?P<parent>T\d+)(?:\.(?P<sub>.+))?$", re.IGNORECASE)


def attack_technique_url(technique_id: Optional[str]) -> Optional[str]:
    """
    Return the attack.mitre.org URL for a technique ID, or None if not parseable.

    Examples:
        T1059 -> .../techniques/T1059/
        T1059.001 -> .../techniques/T1059/001/
    """
    if not technique_id:
        return None
    s = str(technique_id).strip()
    if not s:
        return None
    m = _RE_TECH.match(s.upper())
    if not m:
        return None
    parent = m.group("parent").upper()
    sub = m.group("sub")
    if sub:
        # Normalize sub-id segments (e.g. 001)
        sub_clean = sub.strip()
        return f"{_BASE}/{parent}/{sub_clean}/"
    return f"{_BASE}/{parent}/"


def rule_mitre_technique_ids(rule: Any) -> List[str]:
    """Collect technique IDs from a RuleImplementation-like object."""
    out: List[str] = []
    ids = getattr(rule, "mitre_technique_ids", None)
    if ids and isinstance(ids, list):
        for x in ids:
            if x:
                out.append(str(x).strip())
    legacy = getattr(rule, "mitre_technique_id", None)
    if legacy and str(legacy).strip():
        s = str(legacy).strip()
        if s not in out:
            out.append(s)
    return out


def technique_links_markdown(technique_ids: Iterable[str]) -> str:
    """Comma-separated markdown links for Streamlit ``st.markdown``."""
    parts: List[str] = []
    seen = set()
    for raw in technique_ids:
        if not raw:
            continue
        tid = str(raw).strip()
        if not tid or tid in seen:
            continue
        seen.add(tid)
        url = attack_technique_url(tid)
        if url:
            parts.append(f"[{tid}]({url})")
        else:
            parts.append(f"`{tid}`")
    return ", ".join(parts) if parts else "—"
