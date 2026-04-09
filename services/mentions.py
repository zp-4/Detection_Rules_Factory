"""Parse @mentions and validate against RBAC usernames."""
from __future__ import annotations

import re
from typing import List, Set

_MENTION_RE = re.compile(r"@([\w.-]+)")


def extract_mention_tokens(body: str) -> List[str]:
    if not body:
        return []
    return [m.group(1) for m in _MENTION_RE.finditer(body)]


def resolve_mentions(body: str, known_users: Set[str]) -> List[str]:
    """Return unique usernames that exist in known_users (case-sensitive match to RBAC keys)."""
    seen = set()
    out: List[str] = []
    for raw in extract_mention_tokens(body):
        if raw in known_users and raw not in seen:
            seen.add(raw)
            out.append(raw)
    return out
