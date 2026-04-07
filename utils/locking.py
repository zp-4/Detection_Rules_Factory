"""Locking utilities for preventing concurrent operations."""
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from db.models import AiLock


LOCK_TTL_MINUTES = 30  # Lock expires after 30 minutes


def acquire_ai_lock(
    db: Session,
    rule_id: int,
    rule_hash: str,
    locked_by: str,
    ttl_minutes: int = LOCK_TTL_MINUTES
) -> Optional[AiLock]:
    """
    Acquire a lock for AI analysis on a rule.
    
    Returns:
        AiLock if acquired, None if already locked
    """
    # Clean expired locks first
    cleanup_expired_locks(db)
    
    # Check for existing active lock
    existing = db.query(AiLock).filter(
        AiLock.rule_hash == rule_hash,
        AiLock.expires_at > datetime.utcnow(),
        AiLock.status == "RUNNING"
    ).first()
    
    if existing:
        return None  # Already locked
    
    # Create new lock
    lock = AiLock(
        rule_id=rule_id,
        rule_hash=rule_hash,
        locked_by=locked_by,
        locked_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=ttl_minutes),
        status="RUNNING"
    )
    db.add(lock)
    db.commit()
    db.refresh(lock)
    return lock


def release_ai_lock(db: Session, lock_id: int, status: str = "COMPLETED"):
    """Release an AI lock."""
    lock = db.query(AiLock).filter(AiLock.id == lock_id).first()
    if lock:
        lock.status = status
        lock.expires_at = datetime.utcnow()  # Expire immediately
        db.commit()


def cleanup_expired_locks(db: Session):
    """Clean up expired locks."""
    db.query(AiLock).filter(
        AiLock.expires_at < datetime.utcnow()
    ).update({"status": "EXPIRED"})
    db.commit()


def is_locked(db: Session, rule_hash: str) -> bool:
    """Check if a rule is currently locked."""
    cleanup_expired_locks(db)
    lock = db.query(AiLock).filter(
        AiLock.rule_hash == rule_hash,
        AiLock.expires_at > datetime.utcnow(),
        AiLock.status == "RUNNING"
    ).first()
    return lock is not None

