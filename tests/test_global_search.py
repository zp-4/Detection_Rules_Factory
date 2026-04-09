from __future__ import annotations

from dataclasses import dataclass

from services.global_search import global_search_in_memory


@dataclass
class _Rule:
    id: int
    rule_name: str
    rule_text: str
    platform: str
    mitre_technique_id: str | None
    mitre_technique_ids: list[str] | None
    tags: list[str] | None


@dataclass
class _UseCase:
    id: int
    name: str
    description: str
    status: str
    mitre_claimed: list[str] | None


@dataclass
class _Comment:
    id: int
    author: str
    entity_type: str
    entity_id: int
    body: str


def test_global_search_in_memory_matches_all_sections() -> None:
    results = global_search_in_memory(
        rules=[
            _Rule(
                id=1,
                rule_name="PowerShell encoded command",
                rule_text="detect suspicious powershell",
                platform="windows",
                mitre_technique_id="T1059.001",
                mitre_technique_ids=None,
                tags=["to_improve"],
            )
        ],
        use_cases=[
            _UseCase(
                id=10,
                name="PowerShell abuse",
                description="Lateral movement with scripts",
                status="review",
                mitre_claimed=["T1059.001"],
            )
        ],
        comments=[
            _Comment(
                id=100,
                author="alice",
                entity_type="rule",
                entity_id=1,
                body="Need stronger PowerShell parent process logic.",
            )
        ],
        query="powershell",
        limit_per_type=20,
    )

    assert len(results.rules) == 1
    assert len(results.use_cases) == 1
    assert len(results.comments) == 1


def test_global_search_in_memory_min_chars_and_limits() -> None:
    short = global_search_in_memory(rules=[], use_cases=[], comments=[], query="a", limit_per_type=20)
    assert short.rules == []
    assert short.use_cases == []
    assert short.techniques == []
    assert short.comments == []

    results = global_search_in_memory(
        rules=[
            _Rule(i, f"Rule {i}", "detect", "linux", "T1110", None, None)
            for i in range(10)
        ],
        use_cases=[],
        comments=[],
        query="T1110",
        limit_per_type=3,
    )
    assert len(results.rules) == 3
    assert len(results.techniques) == 3
