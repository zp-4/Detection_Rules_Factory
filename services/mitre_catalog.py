"""MITRE ATT&CK catalogue helpers: tactics, sub-techniques, technique sets."""
from __future__ import annotations

from typing import Any, List, Optional, Set

from db.models import RuleImplementation


def technique_external_id(obj: Any) -> Optional[str]:
    """Return ATT&CK technique ID (e.g. T1059.001) from an AttackPattern-like object."""
    for r in getattr(obj, "external_references", []) or []:
        if getattr(r, "source_name", None) == "mitre-attack":
            eid = getattr(r, "external_id", None)
            if eid:
                return str(eid)
    return None


def technique_tactic_shortnames(obj: Any) -> Set[str]:
    """Return kill-chain phase shortnames (e.g. execution) for the technique."""
    out: Set[str] = set()
    for p in getattr(obj, "kill_chain_phases", []) or []:
        pn = getattr(p, "phase_name", None)
        if isinstance(p, dict) and not pn:
            pn = p.get("phase_name")
        if pn:
            out.add(str(pn))
    return out


def list_tactic_shortnames(mitre_attack_data: Any) -> List[str]:
    """Sorted tactic shortnames (x_mitre_shortname) for multiselects."""
    names: List[str] = []
    for t in mitre_attack_data.get_tactics():
        sn = getattr(t, "x_mitre_shortname", None)
        if sn:
            names.append(str(sn))
    return sorted(names)


def compute_allowed_technique_ids(
    mitre_attack_data: Any,
    tactic_shortnames: Set[str],
    include_subtechniques: bool,
) -> Set[str]:
    """
    Techniques that belong to any of the given tactics (phase shortnames).
    If ``tactic_shortnames`` is empty, returns all technique IDs (respecting sub-technique flag).
    """
    allowed: Set[str] = set()
    techs = mitre_attack_data.get_techniques(
        include_subtechniques=True, remove_revoked_deprecated=True
    )
    for obj in techs:
        if not include_subtechniques and getattr(
            obj, "x_mitre_is_subtechnique", False
        ):
            continue
        tacts = technique_tactic_shortnames(obj)
        if tactic_shortnames and not (tacts & tactic_shortnames):
            continue
        tid = technique_external_id(obj)
        if tid:
            allowed.add(tid)
    return allowed


def collect_rule_technique_ids(rule: RuleImplementation) -> Set[str]:
    """All MITRE IDs declared on a rule (primary + multi)."""
    s: Set[str] = set()
    if rule.mitre_technique_id:
        s.add(str(rule.mitre_technique_id).strip())
    mids = rule.mitre_technique_ids
    if isinstance(mids, list):
        for x in mids:
            if isinstance(x, str) and x.strip():
                s.add(x.strip())
    return s


def collect_covered_technique_ids(rules: List[RuleImplementation]) -> Set[str]:
    """Union of all technique IDs covered by rules."""
    u: Set[str] = set()
    for r in rules:
        u |= collect_rule_technique_ids(r)
    return u


def rule_matches_allowed_techniques(
    rule: RuleImplementation, allowed: Set[str]
) -> bool:
    """True if any of the rule's technique IDs is in ``allowed``."""
    return bool(collect_rule_technique_ids(rule) & allowed)
