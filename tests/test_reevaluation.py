from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from services.reevaluation import summarize_quarterly_queue


@dataclass
class _Rule:
    tags: list[str] | None
    last_audit_results: dict | None


def test_summarize_quarterly_queue_counts_missing_and_overdue() -> None:
    now = datetime(2026, 4, 9, 12, 0, 0)  # Q2 2026 starts on 2026-04-01
    rules = [
        _Rule(tags=["to_improve"], last_audit_results={"analyzed_at": "2026-01-20T10:00:00Z"}),  # overdue
        _Rule(tags=["to_improve"], last_audit_results={"analyzed_at": "2026-04-05T10:00:00Z"}),  # fresh
        _Rule(tags=["to_improve"], last_audit_results=None),  # missing
        _Rule(tags=["prod"], last_audit_results={"analyzed_at": "2025-12-01T00:00:00Z"}),  # not queued
    ]

    summary = summarize_quarterly_queue(rules, now=now)

    assert summary.quarter_label == "Q2 2026"
    assert summary.queued_rules == 2
    assert summary.overdue_rules == 1
    assert summary.missing_audit_date == 1


def test_summarize_quarterly_queue_handles_invalid_dates() -> None:
    now = datetime(2026, 4, 9, 12, 0, 0)
    rules = [
        _Rule(tags=["to_improve"], last_audit_results={"analyzed_at": "not-a-date"}),
        _Rule(tags=["to_improve"], last_audit_results={"run_at": ""}),
    ]

    summary = summarize_quarterly_queue(rules, now=now)

    assert summary.queued_rules == 2
    assert summary.missing_audit_date == 2
    assert summary.overdue_rules == 0
