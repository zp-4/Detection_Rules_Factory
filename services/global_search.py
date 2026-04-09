"""Global search across rules, use cases, techniques and comments."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class GlobalSearchResults:
    rules: list[dict[str, Any]]
    use_cases: list[dict[str, Any]]
    techniques: list[dict[str, Any]]
    comments: list[dict[str, Any]]


def _text(v: Any) -> str:
    return str(v or "").strip()


def _contains(hay: str, needle: str) -> bool:
    return needle in hay.casefold()


def _rule_techniques(rule: Any) -> list[str]:
    out: list[str] = []
    legacy = _text(getattr(rule, "mitre_technique_id", ""))
    if legacy:
        out.append(legacy)
    many = getattr(rule, "mitre_technique_ids", None)
    if isinstance(many, list):
        for t in many:
            s = _text(t)
            if s and s not in out:
                out.append(s)
    return out


def global_search_in_memory(
    *,
    rules: list[Any],
    use_cases: list[Any],
    comments: list[Any],
    query: str,
    limit_per_type: int = 20,
) -> GlobalSearchResults:
    q = _text(query).casefold()
    if len(q) < 2:
        return GlobalSearchResults([], [], [], [])

    rule_rows: list[dict[str, Any]] = []
    tech_rows: list[dict[str, Any]] = []
    use_case_rows: list[dict[str, Any]] = []
    comment_rows: list[dict[str, Any]] = []

    for r in rules:
        rid = int(getattr(r, "id", 0) or 0)
        rname = _text(getattr(r, "rule_name", ""))
        rtext = _text(getattr(r, "rule_text", ""))
        platform = _text(getattr(r, "platform", ""))
        techs = _rule_techniques(r)
        tags = getattr(r, "tags", None)
        tags = tags if isinstance(tags, list) else []
        if (
            _contains(rname, q)
            or _contains(rtext, q)
            or _contains(platform, q)
            or any(_contains(t, q) for t in techs)
            or any(_contains(_text(t), q) for t in tags)
        ):
            rule_rows.append(
                {
                    "id": rid,
                    "rule_name": rname or "Unnamed rule",
                    "platform": platform or "—",
                    "techniques": techs,
                }
            )
        for tid in techs:
            if _contains(tid, q):
                tech_rows.append(
                    {
                        "rule_id": rid,
                        "rule_name": rname or "Unnamed rule",
                        "technique_id": tid,
                    }
                )

    for uc in use_cases:
        uid = int(getattr(uc, "id", 0) or 0)
        name = _text(getattr(uc, "name", ""))
        desc = _text(getattr(uc, "description", ""))
        status = _text(getattr(uc, "status", ""))
        claims = getattr(uc, "mitre_claimed", None)
        claims = claims if isinstance(claims, list) else []
        if (
            _contains(name, q)
            or _contains(desc, q)
            or _contains(status, q)
            or any(_contains(_text(t), q) for t in claims)
        ):
            use_case_rows.append(
                {
                    "id": uid,
                    "name": name or "Unnamed use case",
                    "status": status or "—",
                    "mitre_claimed": [_text(t) for t in claims if _text(t)],
                }
            )

    for c in comments:
        cid = int(getattr(c, "id", 0) or 0)
        body = _text(getattr(c, "body", ""))
        author = _text(getattr(c, "author", ""))
        etype = _text(getattr(c, "entity_type", ""))
        eid = int(getattr(c, "entity_id", 0) or 0)
        if _contains(body, q) or _contains(author, q):
            comment_rows.append(
                {
                    "id": cid,
                    "author": author or "unknown",
                    "entity_type": etype or "—",
                    "entity_id": eid,
                    "preview": body[:180] + ("..." if len(body) > 180 else ""),
                }
            )

    def _cap(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return rows[: max(1, limit_per_type)]

    # De-dup technique matches (same rule_id + technique_id)
    seen: set[tuple[int, str]] = set()
    unique_tech_rows: list[dict[str, Any]] = []
    for row in tech_rows:
        key = (int(row["rule_id"]), str(row["technique_id"]))
        if key in seen:
            continue
        seen.add(key)
        unique_tech_rows.append(row)

    return GlobalSearchResults(
        rules=_cap(rule_rows),
        use_cases=_cap(use_case_rows),
        techniques=_cap(unique_tech_rows),
        comments=_cap(comment_rows),
    )


def search_global(db: Any, query: str, limit_per_type: int = 20) -> GlobalSearchResults:
    from db.models import Comment, RuleImplementation, UseCase

    rules = (
        db.query(RuleImplementation)
        .filter(RuleImplementation.archived_at.is_(None))
        .all()
    )
    use_cases = db.query(UseCase).all()
    comments = db.query(Comment).all()
    return global_search_in_memory(
        rules=rules,
        use_cases=use_cases,
        comments=comments,
        query=query,
        limit_per_type=limit_per_type,
    )
