"""Tests for Sigma Git import helpers."""
import uuid

import pytest

from services.sigma_git_import import (
    ParsedSigma,
    import_sigma_from_directory,
    parse_sigma_yaml,
)
from db.session import SessionLocal, init_db
from db.repo import RuleRepository
from utils.hashing import compute_rule_hash


SAMPLE_SIGMA = """title: Suspicious Test
id: test-rule
status: experimental
description: unit test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\\\evil.exe'
  condition: selection
tags:
  - attack.t1059
level: high
"""


def test_parse_sigma_yaml_extracts_title_platform_mitre():
    p = parse_sigma_yaml(SAMPLE_SIGMA, "x.yml")
    assert p is not None
    assert isinstance(p, ParsedSigma)
    assert "Suspicious Test" in p.title
    assert p.platform == "Windows"
    assert "T1059" in p.mitre_technique_ids
    assert "sigma" in p.rule_text.lower() or "detection:" in p.rule_text


def test_parse_sigma_yaml_rejects_non_rule():
    assert parse_sigma_yaml("foo: bar\n", "n.yml") is None


@pytest.fixture
def db():
    init_db()
    s = SessionLocal()
    yield s
    s.close()


def test_import_from_temp_dir_creates_rule(db, tmp_path):
    unique = uuid.uuid4().hex[:10]
    body = SAMPLE_SIGMA.replace("Suspicious Test", f"Suspicious Test {unique}")
    f = tmp_path / "r.yml"
    f.write_text(body, encoding="utf-8")
    stats = import_sigma_from_directory(db, tmp_path, subdirectory="")
    assert stats.created == 1
    assert stats.skipped_duplicate == 0
    rh = compute_rule_hash(body.strip(), "Windows", "sigma")
    r = RuleRepository.get_by_hash(db, rh)
    assert r is not None
    assert r.rule_format == "sigma"

    stats2 = import_sigma_from_directory(db, tmp_path, subdirectory="")
    assert stats2.created == 0
    assert stats2.skipped_duplicate == 1
