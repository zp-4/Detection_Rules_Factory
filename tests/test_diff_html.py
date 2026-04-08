"""Tests for HTML diff utilities."""
from utils.diff_html import escape_html_diff, generate_colored_diff, generate_side_by_side_diff


def test_escape_html():
    assert "&lt;script&gt;" in escape_html_diff("<script>")


def test_colored_diff_no_change():
    assert generate_colored_diff("same", "same") is None


def test_colored_diff_detects_change():
    html = generate_colored_diff("a\n", "b\n")
    assert html is not None
    assert "diff-" in html


def test_side_by_side_contains_both():
    html = generate_side_by_side_diff("old", "new")
    assert "old" in html and "new" in html
