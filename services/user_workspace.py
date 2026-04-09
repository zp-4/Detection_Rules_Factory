"""Per-user workspace: use cases and rules scoped to ownership / review."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Tuple

from sqlalchemy.orm import Session

from db.models import RuleImplementation, UseCase


def _in_json_list(username: str, lst) -> bool:
    if not lst or not isinstance(lst, list):
        return False
    return username in lst


def use_cases_owned_by(db: Session, username: str) -> List[UseCase]:
    return [uc for uc in db.query(UseCase).all() if _in_json_list(username, uc.owners)]


def use_cases_where_reviewer(db: Session, username: str) -> List[UseCase]:
    return [uc for uc in db.query(UseCase).all() if _in_json_list(username, uc.reviewers)]


def rule_ids_under_use_cases(db: Session, use_case_ids: List[int]) -> List[RuleImplementation]:
    if not use_case_ids:
        return []
    return (
        db.query(RuleImplementation)
        .filter(RuleImplementation.use_case_id.in_(use_case_ids))
        .all()
    )


def rules_needing_attention(rules: List[RuleImplementation]) -> List[RuleImplementation]:
    out: List[RuleImplementation] = []
    for r in rules:
        tags = r.tags or []
        if not isinstance(tags, list):
            continue
        if "to_improve" in tags or "to_update_mapping" in tags:
            out.append(r)
    return out


def use_cases_in_review_for_reviewer(db: Session, username: str) -> List[UseCase]:
    """Use cases where ``username`` is a reviewer and status is ``review``."""
    return [
        uc
        for uc in use_cases_where_reviewer(db, username)
        if (uc.status or "").lower() == "review"
    ]


def review_queue_rows_for_reviewer(db: Session, username: str) -> List[Dict[str, Any]]:
    """
    Review queue sorted: overdue and higher priority first.
    Each row: use_case, priority, due_at, overdue, assignee.
    """
    now = datetime.utcnow()
    rows: List[Dict[str, Any]] = []
    for uc in use_cases_in_review_for_reviewer(db, username):
        due = getattr(uc, "review_due_at", None)
        overdue = False
        if due is not None:
            overdue = due < now
        pri = getattr(uc, "review_priority", None) or 3
        rows.append(
            {
                "use_case": uc,
                "priority": pri,
                "due_at": due,
                "overdue": overdue,
                "assignee": getattr(uc, "review_assignee", None),
            }
        )

    far = datetime(9999, 12, 31)

    def sort_key(r: Dict[str, Any]):
        due = r["due_at"] or far
        return (-(1 if r["overdue"] else 0), r["priority"], due)

    rows.sort(key=sort_key)
    return rows


def workspace_summary(db: Session, username: str) -> Tuple[int, int, int, int]:
    """
    Returns:
        (owned_use_cases, reviewer_use_cases, scoped_rules_count, attention_rules_count)
    """
    owned = use_cases_owned_by(db, username)
    review = use_cases_where_reviewer(db, username)
    uc_ids = {uc.id for uc in owned} | {uc.id for uc in review}
    rules = rule_ids_under_use_cases(db, list(uc_ids))
    attention = rules_needing_attention(rules)
    return len(owned), len(review), len(rules), len(attention)
