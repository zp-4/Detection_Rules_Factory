"""Outbound webhooks for integration events (Slack, Teams, etc.)."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests
import yaml

from db.models import MappingReview, RuleImplementation

logger = logging.getLogger(__name__)

WEBHOOKS_PATH = os.path.join("config", "webhooks.yaml")


def _defaults() -> Dict[str, Any]:
    return {
        "enabled": False,
        "endpoints": [],
        "timeout_seconds": 8,
        "retries": 2,
        "retry_backoff_seconds": 1.2,
        "signing_secret_env": "",
    }


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


def _secret_from_env(secret_env: str) -> str:
    key = str(secret_env or "").strip()
    if not key:
        return ""
    return str(os.getenv(key, "")).strip()


def _sign_payload(*, secret: str, timestamp: str, body_bytes: bytes) -> str:
    msg = timestamp.encode("utf-8") + b"." + body_bytes
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def _json_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _should_retry(status_code: int) -> bool:
    return status_code == 429 or status_code >= 500


def dispatch(event: str, data: Dict[str, Any]) -> None:
    """POST signed JSON to each endpoint; retries on transient errors."""
    cfg = load_webhook_config()
    if not cfg.get("enabled"):
        return
    timeout = float(cfg.get("timeout_seconds", 8) or 8)
    retries = int(cfg.get("retries", 2) or 2)
    backoff = float(cfg.get("retry_backoff_seconds", 1.2) or 1.2)

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
        payload = {
            "event": event,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        body = _json_bytes(payload)
        timestamp = datetime.now(timezone.utc).isoformat()
        secret_env = str(ep.get("signing_secret_env") or cfg.get("signing_secret_env") or "").strip()
        secret = _secret_from_env(secret_env)
        headers = {
            "Content-Type": "application/json",
            "X-DRF-Event": event,
            "X-DRF-Timestamp": timestamp,
        }
        if secret:
            headers["X-DRF-Signature"] = _sign_payload(
                secret=secret,
                timestamp=timestamp,
                body_bytes=body,
            )

        max_attempts = max(1, retries + 1)
        for attempt in range(1, max_attempts + 1):
            try:
                resp = requests.post(url, data=body, headers=headers, timeout=timeout)
                if _should_retry(int(resp.status_code)) and attempt < max_attempts:
                    time.sleep(backoff * attempt)
                    continue
                if int(resp.status_code) >= 400:
                    logger.warning(
                        "webhook POST failed for %s: status=%s",
                        url[:48],
                        resp.status_code,
                    )
                break
            except Exception as ex:
                if attempt < max_attempts:
                    time.sleep(backoff * attempt)
                    continue
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
