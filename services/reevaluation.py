"""Quarterly reevaluation queue for rules tagged `to_improve`."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class QuarterlyReevaluationSummary:
    quarter_label: str
    queued_rules: int
    overdue_rules: int
    missing_audit_date: int


def _coerce_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not value or not isinstance(value, str):
        return None
    txt = value.strip()
    if not txt:
        return None
    if txt.endswith("Z"):
        txt = txt[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(txt)
    except ValueError:
        return None


def _utc_naive(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def quarter_start(reference: datetime) -> datetime:
    month = ((reference.month - 1) // 3) * 3 + 1
    return datetime(reference.year, month, 1)


def quarter_label(reference: datetime) -> str:
    q = ((reference.month - 1) // 3) + 1
    return f"Q{q} {reference.year}"


def summarize_quarterly_queue(rules: list[Any], now: datetime | None = None) -> QuarterlyReevaluationSummary:
    """
    Build a quarterly queue summary from rule rows.

    Rules are queued when tagged `to_improve` and their last audit date is
    missing or older than the current quarter start.
    """
    ref = _utc_naive(now or datetime.now(timezone.utc))
    q_start = quarter_start(ref)
    q_label = quarter_label(ref)

    queued = 0
    overdue = 0
    missing = 0

    for r in rules:
        tags = getattr(r, "tags", None)
        if not isinstance(tags, list) or "to_improve" not in tags:
            continue

        audit_meta = getattr(r, "last_audit_results", None) or {}
        if not isinstance(audit_meta, dict):
            audit_meta = {}

        audited_at = _coerce_dt(audit_meta.get("analyzed_at"))
        if audited_at is None:
            audited_at = _coerce_dt(audit_meta.get("run_at"))
        if audited_at is None:
            audited_at = _coerce_dt(audit_meta.get("audited_at"))

        if audited_at is None:
            queued += 1
            missing += 1
            continue

        audited_at = _utc_naive(audited_at)
        if audited_at < q_start:
            queued += 1
            overdue += 1

    return QuarterlyReevaluationSummary(
        quarter_label=q_label,
        queued_rules=queued,
        overdue_rules=overdue,
        missing_audit_date=missing,
    )
