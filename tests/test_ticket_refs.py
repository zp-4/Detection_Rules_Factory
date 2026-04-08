"""External ticket reference parsing."""
import json

import pytest

from services.ticket_refs import parse_ticket_refs_json, ticket_refs_to_display_lines


def test_parse_empty():
    assert parse_ticket_refs_json("") == []
    assert parse_ticket_refs_json("   ") == []


def test_parse_valid_minimal():
    r = parse_ticket_refs_json('[{"system":"jira","key":"X-1"}]')
    assert r == [{"system": "jira", "key": "X-1"}]


def test_parse_with_url():
    raw = json.dumps(
        [{"system": "linear", "key": "SEC-2", "url": "https://linear.app/i/1"}]
    )
    r = parse_ticket_refs_json(raw)
    assert r[0]["url"].startswith("https://")


def test_parse_rejects_bad_system():
    assert parse_ticket_refs_json('[{"system":"unknown"}]') is None


def test_parse_rejects_non_http_url():
    assert parse_ticket_refs_json('[{"system":"jira","url":"ftp://x"}]') is None


def test_display_lines():
    lines = ticket_refs_to_display_lines(
        [{"system": "jira", "key": "A", "url": "https://x/y"}]
    )
    assert any("jira" in x for x in lines)
