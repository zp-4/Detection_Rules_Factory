"""Explainability helpers for dashboard snippets."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from utils.mitre_links import rule_mitre_technique_ids


@dataclass(frozen=True)
class ExplainabilityItem:
    rule_id: int
    rule_name: str
    summary_sentence: str
    technique_ids: list[str]


def one_sentence_summary(last_audit_results: Any) -> str:
    """Return one concise sentence from audit payload."""
    if not isinstance(last_audit_results, dict):
        return "No AI audit summary available yet."

    gap = str(last_audit_results.get("gap_analysis") or "").strip()
    improve = str(last_audit_results.get("improvement_suggestion") or "").strip()

    def _clean(txt: str) -> str:
        txt = " ".join(txt.split())
        if not txt:
            return ""
        if txt.lower() == "n/a":
            return ""
        return txt.rstrip(".")

    gap = _clean(gap)
    improve = _clean(improve)

    if gap and improve:
        return f"Gap: {gap}. Suggested improvement: {improve}."
    if gap:
        return f"Gap: {gap}."
    if improve:
        return f"Suggested improvement: {improve}."
    return "No AI audit summary available yet."


def top_explainability_items(rules: list[Any], limit: int = 4) -> list[ExplainabilityItem]:
    """
    Pick top rules for explainability panel.
    Prioritize `to_improve` tagged rules; fallback to latest audited rules.
    """
    tagged: list[Any] = []
    others: list[Any] = []
    for r in rules:
        tags = getattr(r, "tags", None)
        has_to_improve = isinstance(tags, list) and ("to_improve" in tags)
        if has_to_improve:
            tagged.append(r)
        else:
            others.append(r)

    selected = (tagged + others)[: max(0, limit)]
    out: list[ExplainabilityItem] = []
    for r in selected:
        rid = int(getattr(r, "id", 0) or 0)
        name = str(getattr(r, "rule_name", "Unnamed rule") or "Unnamed rule")
        audit = getattr(r, "last_audit_results", None)
        out.append(
            ExplainabilityItem(
                rule_id=rid,
                rule_name=name,
                summary_sentence=one_sentence_summary(audit),
                technique_ids=rule_mitre_technique_ids(r),
            )
        )
    return out
