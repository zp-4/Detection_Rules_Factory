"""Quota management service."""
from sqlalchemy.orm import Session
from db.repo import QuotaRepository
from utils.time import get_current_period


def check_quota(db: Session, team: str) -> tuple[bool, int, int]:
    """
    Check if team has quota available.
    
    Returns:
        (has_quota, used, limit)
    """
    period = get_current_period()
    quota = QuotaRepository.get_or_create(db, period, team)
    has_quota = quota.runs_used < quota.runs_limit
    return has_quota, quota.runs_used, quota.runs_limit


def consume_quota(db: Session, team: str) -> bool:
    """Consume one quota unit. Returns True if successful."""
    period = get_current_period()
    return QuotaRepository.increment_usage(db, period, team)


def set_quota_limit(db: Session, team: str, limit: int):
    """Set quota limit for team."""
    period = get_current_period()
    QuotaRepository.set_limit(db, period, team, limit)

