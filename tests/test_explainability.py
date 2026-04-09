from __future__ import annotations

from dataclasses import dataclass

from services.explainability import one_sentence_summary, top_explainability_items


@dataclass
class _Rule:
    id: int
    rule_name: str
    tags: list[str] | None
    last_audit_results: dict | None
    mitre_technique_id: str | None = None
    mitre_technique_ids: list[str] | None = None


def test_one_sentence_summary_combines_gap_and_suggestion() -> None:
    text = one_sentence_summary(
        {
            "gap_analysis": "Missing process parent correlation. ",
            "improvement_suggestion": "Add parent-child process checks.",
        }
    )
    assert text == (
        "Gap: Missing process parent correlation. "
        "Suggested improvement: Add parent-child process checks."
    )


def test_top_explainability_items_prioritizes_to_improve() -> None:
    rules = [
        _Rule(
            id=1,
            rule_name="Rule A",
            tags=["prod"],
            last_audit_results={"gap_analysis": "N/A"},
            mitre_technique_id="T1059",
        ),
        _Rule(
            id=2,
            rule_name="Rule B",
            tags=["to_improve"],
            last_audit_results={"improvement_suggestion": "Tune threshold"},
            mitre_technique_ids=["T1110.001"],
        ),
    ]

    items = top_explainability_items(rules, limit=2)
    assert len(items) == 2
    assert items[0].rule_id == 2
    assert items[0].technique_ids == ["T1110.001"]
    assert items[1].rule_id == 1
