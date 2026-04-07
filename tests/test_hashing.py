"""Tests for hashing utilities."""
import pytest
from utils.hashing import compute_rule_hash, normalize_rule_text


def test_normalize_rule_text():
    """Test rule text normalization."""
    rule1 = 'ProcessName == "cmd.exe"'
    rule2 = "ProcessName == 'cmd.exe'"
    rule3 = 'ProcessName  ==  "cmd.exe"  '
    
    norm1 = normalize_rule_text(rule1)
    norm2 = normalize_rule_text(rule2)
    norm3 = normalize_rule_text(rule3)
    
    # Should normalize quotes and whitespace
    assert norm1 == norm2  # Single vs double quotes
    assert norm1 == norm3  # Extra whitespace


def test_compute_rule_hash():
    """Test rule hash computation."""
    rule_text = 'ProcessName == "cmd.exe"'
    platform = "Windows"
    rule_format = "splunk"
    
    hash1 = compute_rule_hash(rule_text, platform, rule_format)
    hash2 = compute_rule_hash(rule_text, platform, rule_format)
    
    # Same input should produce same hash
    assert hash1 == hash2
    assert len(hash1) == 64  # SHA256 hex length
    
    # Different platform should produce different hash
    hash3 = compute_rule_hash(rule_text, "Linux", rule_format)
    assert hash1 != hash3

