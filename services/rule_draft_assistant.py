"""Natural-language → rule skeleton assistant (quota-aware)."""
from __future__ import annotations

from typing import Any, Dict

from sqlalchemy.orm import Session

from src.ai_engine import AIEngine
from services.auth import get_current_user, get_user_team
from services.quota import check_quota, consume_quota


def run_rule_draft_assistant(
    db: Session,
    ai_engine: AIEngine,
    description: str,
    preferred_platform: str = "Windows",
    preferred_format: str = "sigma",
) -> Dict[str, Any]:
    """
    Call the LLM to draft a rule + MITRE hints + FP checklist.
    Consumes one AI quota unit only when a usable draft is returned.
    """
    username = get_current_user()
    team = get_user_team(username)
    if not team:
        return {"error": "User team is not set in RBAC (config/rbac.yaml)."}

    has_quota, used, limit = check_quota(db, team)
    if not has_quota:
        return {
            "error": f"Monthly AI quota exceeded ({used}/{limit} runs). Contact an administrator.",
        }

    text = (description or "").strip()
    if len(text) < 10:
        return {"error": "Please enter a longer description (at least a few words)."}

    raw = ai_engine.draft_rule_from_natural_language(
        text,
        preferred_platform=preferred_platform,
        preferred_format=preferred_format,
    )

    if raw.get("error") and not raw.get("rule_text"):
        return raw

    if raw.get("not_applicable"):
        return raw

    if not (raw.get("rule_text") or "").strip():
        return {**raw, "error": "Model returned an empty draft."}

    if not consume_quota(db, team):
        return {"error": "Could not record quota usage; try again."}

    return raw
