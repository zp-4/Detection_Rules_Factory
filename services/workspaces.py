"""Workspace reporting by team (BU/region abstraction)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class WorkspaceRow:
    workspace: str
    users: int
    use_cases_owned: int
    use_cases_reviewed: int
    rules_in_scope: int
    rules_to_improve: int


def _teams_by_user(rbac_users: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for uname, payload in (rbac_users or {}).items():
        if not isinstance(payload, dict):
            continue
        team = str(payload.get("team") or "").strip() or "unassigned"
        out[str(uname)] = team
    return out


def _ensure_workspace(stats: dict[str, dict[str, Any]], name: str) -> None:
    if name in stats:
        return
    stats[name] = {
        "users": set(),
        "owned_uc_ids": set(),
        "review_uc_ids": set(),
        "rule_ids": set(),
        "to_improve_rule_ids": set(),
    }


def build_workspace_rows(
    rbac_users: dict[str, Any],
    use_cases: list[Any],
    rules: list[Any],
) -> list[WorkspaceRow]:
    """Aggregate workspace metrics from RBAC users, use cases and rules."""
    user_team = _teams_by_user(rbac_users)
    stats: dict[str, dict[str, Any]] = {}

    for uname, team in user_team.items():
        _ensure_workspace(stats, team)
        stats[team]["users"].add(uname)

    uc_teams: dict[int, set[str]] = {}
    for uc in use_cases:
        uc_id = int(getattr(uc, "id", 0) or 0)
        owners = getattr(uc, "owners", None)
        reviewers = getattr(uc, "reviewers", None)
        owners = owners if isinstance(owners, list) else []
        reviewers = reviewers if isinstance(reviewers, list) else []

        teams_for_uc: set[str] = set()
        for uname in owners:
            team = user_team.get(str(uname), "unassigned")
            _ensure_workspace(stats, team)
            stats[team]["owned_uc_ids"].add(uc_id)
            teams_for_uc.add(team)
        for uname in reviewers:
            team = user_team.get(str(uname), "unassigned")
            _ensure_workspace(stats, team)
            stats[team]["review_uc_ids"].add(uc_id)
            teams_for_uc.add(team)
        if teams_for_uc:
            uc_teams[uc_id] = teams_for_uc

    for rule in rules:
        rid = int(getattr(rule, "id", 0) or 0)
        uc_id = int(getattr(rule, "use_case_id", 0) or 0)
        tags = getattr(rule, "tags", None)
        tags = tags if isinstance(tags, list) else []
        teams = uc_teams.get(uc_id, {"unassigned"})
        for team in teams:
            _ensure_workspace(stats, team)
            stats[team]["rule_ids"].add(rid)
            if "to_improve" in tags:
                stats[team]["to_improve_rule_ids"].add(rid)

    rows: list[WorkspaceRow] = []
    for workspace in sorted(stats.keys()):
        s = stats[workspace]
        rows.append(
            WorkspaceRow(
                workspace=workspace,
                users=len(s["users"]),
                use_cases_owned=len(s["owned_uc_ids"]),
                use_cases_reviewed=len(s["review_uc_ids"]),
                rules_in_scope=len(s["rule_ids"]),
                rules_to_improve=len(s["to_improve_rule_ids"]),
            )
        )
    return rows
