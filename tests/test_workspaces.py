from __future__ import annotations

from dataclasses import dataclass

from services.workspaces import build_workspace_rows


@dataclass
class _UC:
    id: int
    owners: list[str] | None
    reviewers: list[str] | None


@dataclass
class _Rule:
    id: int
    use_case_id: int | None
    tags: list[str] | None


def test_build_workspace_rows_aggregates_by_team() -> None:
    users = {
        "alice": {"team": "soc"},
        "bob": {"team": "security"},
        "charlie": {"team": "soc"},
    }
    use_cases = [
        _UC(id=1, owners=["alice"], reviewers=["bob"]),
        _UC(id=2, owners=["charlie"], reviewers=[]),
    ]
    rules = [
        _Rule(id=10, use_case_id=1, tags=["to_improve"]),
        _Rule(id=11, use_case_id=1, tags=[]),
        _Rule(id=12, use_case_id=2, tags=["to_improve"]),
    ]

    rows = build_workspace_rows(users, use_cases, rules)
    by_ws = {r.workspace: r for r in rows}

    assert by_ws["soc"].users == 2
    assert by_ws["soc"].use_cases_owned == 2
    assert by_ws["soc"].use_cases_reviewed == 0
    assert by_ws["soc"].rules_in_scope == 3
    assert by_ws["soc"].rules_to_improve == 2

    assert by_ws["security"].users == 1
    assert by_ws["security"].use_cases_owned == 0
    assert by_ws["security"].use_cases_reviewed == 1
    assert by_ws["security"].rules_in_scope == 2
    assert by_ws["security"].rules_to_improve == 1


def test_build_workspace_rows_handles_unassigned_users_and_rules() -> None:
    users = {"alice": {"team": "soc"}}
    use_cases = [_UC(id=1, owners=["ghost"], reviewers=None)]
    rules = [_Rule(id=20, use_case_id=1, tags=["to_improve"])]

    rows = build_workspace_rows(users, use_cases, rules)
    by_ws = {r.workspace: r for r in rows}

    assert by_ws["unassigned"].users == 0
    assert by_ws["unassigned"].use_cases_owned == 1
    assert by_ws["unassigned"].rules_in_scope == 1
    assert by_ws["unassigned"].rules_to_improve == 1
