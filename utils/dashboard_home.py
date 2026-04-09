"""Aggregated stats for the signed-in home dashboard (read-only)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import func


@dataclass(frozen=True)
class HomeDashboardStats:
    db_ok: bool
    n_use_cases: int
    n_rules: int
    n_use_cases_in_review: int
    n_cti_entries: int
    n_unread_notifications: int
    n_my_reviews: int
    n_audits_total: int
    n_quarterly_reeval_queue: int
    quarterly_label: str
    explainability_items: list[dict[str, Any]]
    mitre_engine_ok: bool
    use_cases_by_status: dict[str, int]
    error: str | None


def load_home_dashboard_stats(username: str) -> HomeDashboardStats:
    """Best-effort counts; safe when DB or MITRE are unavailable."""
    empty_status: dict[str, int] = {}
    mitre_ok = False
    err: str | None = None

    try:
        from services.mitre_coverage import get_mitre_engine

        get_mitre_engine()
        mitre_ok = True
    except Exception:
        mitre_ok = False

    try:
        from db.session import SessionLocal
        from db.models import UseCase, RuleImplementation, CtiLibraryEntry
        from db.models import OfflineAuditResult, AiAuditResult
        from db.repo import NotificationRepository
        from services.explainability import top_explainability_items
        from services.reevaluation import summarize_quarterly_queue

        db = SessionLocal()
        try:
            n_uc = int(db.query(UseCase).count())
            n_rules = int(db.query(RuleImplementation).count())
            n_review = int(
                db.query(UseCase).filter(UseCase.status == "review").count()
            )
            n_cti = int(db.query(CtiLibraryEntry).count())
            n_unread = int(NotificationRepository.count_unread(db, username))
            n_my_reviews = int(
                db.query(UseCase)
                .filter(
                    UseCase.status == "review",
                    UseCase.review_assignee == username,
                )
                .count()
            )
            n_audits = int(db.query(OfflineAuditResult).count()) + int(
                db.query(AiAuditResult).count()
            )
            all_rules = db.query(RuleImplementation).all()
            reeval = summarize_quarterly_queue(all_rules)
            explain = top_explainability_items(all_rules, limit=4)

            rows = (
                db.query(UseCase.status, func.count(UseCase.id))
                .group_by(UseCase.status)
                .all()
            )
            by_status = {str(s or "unknown"): int(c) for s, c in rows}

            return HomeDashboardStats(
                db_ok=True,
                n_use_cases=n_uc,
                n_rules=n_rules,
                n_use_cases_in_review=n_review,
                n_cti_entries=n_cti,
                n_unread_notifications=n_unread,
                n_my_reviews=n_my_reviews,
                n_audits_total=n_audits,
                n_quarterly_reeval_queue=reeval.queued_rules,
                quarterly_label=reeval.quarter_label,
                explainability_items=[
                    {
                        "rule_id": it.rule_id,
                        "rule_name": it.rule_name,
                        "summary_sentence": it.summary_sentence,
                        "technique_ids": it.technique_ids,
                    }
                    for it in explain
                ],
                mitre_engine_ok=mitre_ok,
                use_cases_by_status=by_status,
                error=err,
            )
        finally:
            db.close()
    except Exception as e:
        return HomeDashboardStats(
            db_ok=False,
            n_use_cases=0,
            n_rules=0,
            n_use_cases_in_review=0,
            n_cti_entries=0,
            n_unread_notifications=0,
            n_my_reviews=0,
            n_audits_total=0,
            n_quarterly_reeval_queue=0,
            quarterly_label="Q? ????",
            explainability_items=[],
            mitre_engine_ok=mitre_ok,
            use_cases_by_status=empty_status,
            error=str(e),
        )
