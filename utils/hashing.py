"""Hashing utilities for rules."""
import hashlib
import json
from typing import Dict, Any


def normalize_rule_text(rule_text: str) -> str:
    """Normalize rule text for hashing (remove whitespace, normalize quotes)."""
    # Remove extra whitespace
    normalized = " ".join(rule_text.split())
    # Normalize quotes (single to double)
    normalized = normalized.replace("'", '"')
    # Lowercase for consistency
    normalized = normalized.lower()
    return normalized


def compute_rule_hash(rule_text: str, platform: str, rule_format: str = "") -> str:
    """
    Compute SHA256 hash of a rule for duplicate detection.
    
    Args:
        rule_text: The rule query/logic text
        platform: Platform name (Windows, Linux, etc.)
        rule_format: Rule format (splunk, sigma, kql, etc.)
    
    Returns:
        SHA256 hash as hex string
    """
    normalized_text = normalize_rule_text(rule_text)
    
    # Create hash input
    hash_input = f"{normalized_text}|{platform.lower()}|{rule_format.lower()}"
    
    # Compute hash
    hash_obj = hashlib.sha256(hash_input.encode('utf-8'))
    return hash_obj.hexdigest()


def compute_dict_hash(data: Dict[str, Any]) -> str:
    """Compute hash of a dictionary (for JSON data)."""
    # Sort keys for consistent hashing
    sorted_json = json.dumps(data, sort_keys=True)
    hash_obj = hashlib.sha256(sorted_json.encode('utf-8'))
    return hash_obj.hexdigest()

