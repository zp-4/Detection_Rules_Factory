"""Tests for locking mechanism."""
import pytest
from datetime import datetime, timedelta
from db.session import SessionLocal, init_db
from utils.locking import acquire_ai_lock, release_ai_lock, is_locked, cleanup_expired_locks
from db.models import AiLock


@pytest.fixture
def db():
    """Create test database session."""
    init_db()
    db = SessionLocal()
    yield db
    # Cleanup
    db.query(AiLock).delete()
    db.commit()
    db.close()


def test_acquire_lock(db):
    """Test lock acquisition."""
    rule_id = 1
    rule_hash = "test_hash_123"
    locked_by = "test_user"
    
    lock = acquire_ai_lock(db, rule_id, rule_hash, locked_by)
    
    assert lock is not None
    assert lock.rule_hash == rule_hash
    assert lock.locked_by == locked_by
    assert lock.status == "RUNNING"


def test_duplicate_lock(db):
    """Test that duplicate locks are prevented."""
    rule_id = 1
    rule_hash = "test_hash_123"
    locked_by = "test_user"
    
    lock1 = acquire_ai_lock(db, rule_id, rule_hash, locked_by)
    assert lock1 is not None
    
    # Try to acquire again
    lock2 = acquire_ai_lock(db, rule_id, rule_hash, locked_by)
    assert lock2 is None  # Should fail


def test_release_lock(db):
    """Test lock release."""
    rule_id = 1
    rule_hash = "test_hash_123"
    locked_by = "test_user"
    
    lock = acquire_ai_lock(db, rule_id, rule_hash, locked_by)
    assert lock is not None
    
    release_ai_lock(db, lock.id, "COMPLETED")
    
    # Check lock is released
    is_locked_result = is_locked(db, rule_hash)
    assert is_locked_result is False

