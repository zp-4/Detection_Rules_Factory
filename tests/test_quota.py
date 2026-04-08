"""Tests for quota management."""
import uuid

import pytest
from db.session import SessionLocal, init_db
from services.quota import check_quota, consume_quota, set_quota_limit
@pytest.fixture
def db():
    """Create test database session."""
    init_db()  # Ensure tables exist
    db = SessionLocal()
    yield db
    db.close()


def _unique_team() -> str:
    return f"test_team_{uuid.uuid4().hex[:12]}"


def test_check_quota(db):
    """Test quota checking."""
    team = _unique_team()
    
    has_quota, used, limit = check_quota(db, team)
    
    # Should have default quota
    assert has_quota is True
    assert used == 0
    assert limit == 10


def test_consume_quota(db):
    """Test quota consumption."""
    team = _unique_team()
    
    # Consume quota
    result1 = consume_quota(db, team)
    assert result1 is True
    
    # Check updated usage
    has_quota, used, limit = check_quota(db, team)
    assert used == 1
    assert has_quota is True


def test_quota_limit(db):
    """Test quota limit setting."""
    team = _unique_team()
    new_limit = 5
    
    set_quota_limit(db, team, new_limit)
    
    has_quota, used, limit = check_quota(db, team)
    assert limit == new_limit

