"""Aggregate metrics for executive PDF / reports (shared with dashboard logic)."""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Set

from sqlalchemy.orm import Session

from db.models import RuleImplementation
from db.repo import UseCaseRepository


def collect_executive_metrics(db: Session, include_archived: bool = False) -> Dict[str, Any]:
    """Return summary counts for PDF and dashboards."""
    rq = db.query(RuleImplementation)
    if not include_archived:
        rq = rq.filter(RuleImplementation.archived_at.is_(None))
    rules: List[RuleImplementation] = rq.all()
    use_cases = UseCaseRepository.list_all(db, limit=5000)

    total_techniques_claimed: Set[str] = set()
    for uc in use_cases:
        if uc.mitre_claimed:
            for tech_id in uc.mitre_claimed:
                total_techniques_claimed.add(tech_id)

    techniques_with_rules: Set[str] = set()
    rules_by_platform: Dict[str, int] = defaultdict(int)
    for rule in rules:
        if rule.mitre_technique_id:
            techniques_with_rules.add(rule.mitre_technique_id)
        if rule.platform:
            rules_by_platform[rule.platform] += 1

    enabled = sum(1 for r in rules if r.enabled)
    to_improve = sum(
        1
        for r in rules
        if r.tags and isinstance(r.tags, list) and "to_improve" in r.tags
    )
    retired = sum(
        1
        for r in rules
        if (getattr(r, "operational_status", None) or "") == "retired"
    )
    archived_count = db.query(RuleImplementation).filter(
        RuleImplementation.archived_at.isnot(None)
    ).count()

    return {
        "use_case_count": len(use_cases),
        "rule_count": len(rules),
        "techniques_claimed_use_cases": len(total_techniques_claimed),
        "techniques_with_rules": len(techniques_with_rules),
        "enabled_rules": enabled,
        "disabled_rules": len(rules) - enabled,
        "rules_to_improve": to_improve,
        "retired_active_view": retired,
        "archived_total": archived_count,
        "platforms": dict(sorted(rules_by_platform.items(), key=lambda x: -x[1])),
    }
