"""Outbound webhooks for integration events (Slack, Teams, etc.)."""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests
import yaml

from db.models import MappingReview, RuleImplementation

logger = logging.getLogger(__name__)

WEBHOOKS_PATH = os.path.join("config", "webhooks.yaml")


def _defaults() -> Dict[str, Any]:
    return {"enabled": False, "endpoints": []}


def load_webhook_config() -> Dict[str, Any]:
    data = _defaults()
    if os.path.exists(WEBHOOKS_PATH):
        try:
            with open(WEBHOOKS_PATH, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f) or {}
            if isinstance(loaded, dict):
                data.update(loaded)
        except Exception:
            pass
    if not isinstance(data.get("endpoints"), list):
        data["endpoints"] = []
    return data


def dispatch(event: str, data: Dict[str, Any]) -> None:
    """POST JSON to each configured endpoint that subscribes to ``event``. Failures are logged only."""
    cfg = load_webhook_config()
    if not cfg.get("enabled"):
        return
    payload = {
        "event": event,
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }
    endpoints: List[Dict[str, Any]] = cfg.get("endpoints") or []
    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        evs = ep.get("events") or []
        if event not in evs:
            continue
        url = (ep.get("url") or "").strip()
        if not url:
            continue
        try:
            requests.post(url, json=payload, timeout=8)
        except Exception as ex:
            logger.warning("webhook POST failed for %s: %s", url[:48], ex)


def emit_use_case_approved(
    use_case_id: int,
    use_case_name: str,
    decided_by: str,
    previous_status: str,
) -> None:
    dispatch(
        "use_case_approved",
        {
            "use_case_id": use_case_id,
            "use_case_name": use_case_name,
            "decided_by": decided_by,
            "previous_status": previous_status,
        },
    )


def emit_mapping_changed(review: MappingReview, rule: RuleImplementation) -> None:
    dispatch(
        "mapping_changed",
        {
            "review_id": review.id,
            "rule_id": rule.id,
            "rule_name": rule.rule_name,
            "reviewed_by": review.reviewed_by,
            "action_type": review.action_type,
            "previous_technique_id": review.previous_technique_id,
            "new_technique_id": review.new_technique_id,
        },
    )


def emit_audit_completed(
    rule_id: int,
    rule_name: str,
    result_id: int,
    confidence: Optional[float],
    kind: str = "offline",
) -> None:
    dispatch(
        "audit_completed",
        {
            "kind": kind,
            "rule_id": rule_id,
            "rule_name": rule_name,
            "result_id": result_id,
            "confidence": confidence,
        },
    )
