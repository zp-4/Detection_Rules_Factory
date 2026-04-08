"""Near-duplicate detection via normalized text similarity (no embeddings)."""
from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Any, Dict, List, Tuple


def normalize_rule_text(text: str) -> str:
    if not text:
        return ""
    t = text.lower()
    t = re.sub(r"\s+", " ", t)
    return t.strip()


def similarity_ratio(a: str, b: str) -> float:
    na, nb = normalize_rule_text(a), normalize_rule_text(b)
    if not na or not nb:
        return 0.0
    return SequenceMatcher(None, na, nb).ratio()


def find_similar_rules(
    rule_text: str,
    rule_id: int,
    candidates: List[Tuple[int, str, str]],
    min_ratio: float = 0.72,
    top_n: int = 25,
) -> List[Dict[str, Any]]:
    """
    candidates: list of (id, rule_name, other_rule_text)
    """
    rows: List[Dict[str, Any]] = []
    for oid, oname, otext in candidates:
        if oid == rule_id:
            continue
        r = similarity_ratio(rule_text, otext)
        if r >= min_ratio:
            rows.append({"rule_id": oid, "rule_name": oname, "similarity": round(r, 4)})
    rows.sort(key=lambda x: -x["similarity"])
    return rows[:top_n]
