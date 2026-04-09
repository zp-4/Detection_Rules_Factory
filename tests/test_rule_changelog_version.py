"""RuleChangeLogRepository.log_update bumps business version when appropriate."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.models import Base, RuleImplementation
from db.repo import RuleChangeLogRepository
from utils.hashing import compute_rule_hash


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def _make_rule(text: str = "q1") -> RuleImplementation:
    h = compute_rule_hash(text, "Windows", "splunk")
    return RuleImplementation(
        platform="Windows",
        rule_name="t-rule",
        rule_text=text,
        rule_format="splunk",
        rule_hash=h,
        version=1,
    )


def test_log_update_bumps_version_on_rule_text_change(db_session):
    rule = _make_rule("alpha")
    db_session.add(rule)
    db_session.commit()
    db_session.refresh(rule)

    prev = RuleChangeLogRepository._rule_to_dict(rule)
    rule.rule_text = "beta"
    rule.rule_hash = compute_rule_hash("beta", "Windows", "splunk")
    db_session.commit()
    db_session.refresh(rule)

    RuleChangeLogRepository.log_update(db_session, rule, prev, "tester")
    db_session.refresh(rule)
    assert rule.version == 2


def test_log_update_no_bump_when_only_last_audit_results(db_session):
    rule = _make_rule("gamma")
    rule.last_audit_results = None
    db_session.add(rule)
    db_session.commit()
    db_session.refresh(rule)

    prev = RuleChangeLogRepository._rule_to_dict(rule)
    rule.last_audit_results = {"analyzed_at": "2020-01-01"}
    db_session.commit()
    db_session.refresh(rule)

    RuleChangeLogRepository.log_update(db_session, rule, prev, "tester")
    db_session.refresh(rule)
    assert rule.version == 1
