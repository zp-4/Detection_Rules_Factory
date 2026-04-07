"""Tests for database operations."""
import pytest
from db.session import SessionLocal, init_db
from db.repo import UseCaseRepository, RuleRepository
from utils.hashing import compute_rule_hash


@pytest.fixture
def db():
    """Create test database session."""
    init_db()
    db = SessionLocal()
    yield db
    db.close()


def test_create_use_case(db):
    """Test use case creation."""
    uc = UseCaseRepository.create(
        db,
        name="Test Use Case",
        description="Test description",
        status="draft"
    )
    
    assert uc.id is not None
    assert uc.name == "Test Use Case"
    assert uc.status == "draft"


def test_get_use_case(db):
    """Test use case retrieval."""
    uc = UseCaseRepository.create(
        db,
        name="Test Use Case",
        description="Test"
    )
    
    retrieved = UseCaseRepository.get_by_id(db, uc.id)
    assert retrieved is not None
    assert retrieved.name == "Test Use Case"


def test_create_rule(db):
    """Test rule creation."""
    # Create use case first
    uc = UseCaseRepository.create(
        db,
        name="Test Use Case",
        description="Test"
    )
    
    rule = RuleRepository.create(
        db,
        use_case_id=uc.id,
        platform="Windows",
        rule_name="Test Rule",
        rule_text='ProcessName == "test.exe"',
        rule_format="splunk",
        rule_hash=compute_rule_hash('ProcessName == "test.exe"', "Windows", "splunk")
    )
    
    assert rule.id is not None
    assert rule.use_case_id == uc.id

