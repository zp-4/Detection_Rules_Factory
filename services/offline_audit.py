"""Offline MITRE audit service."""
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from src.mitre_engine import MitreEngine
from db.repo import OfflineAuditRepository
from db.models import RuleImplementation
from services.webhooks import emit_audit_completed


def run_offline_audit(
    db: Session,
    rule: RuleImplementation,
    mitre_engine: MitreEngine
) -> Dict[str, Any]:
    """
    Run offline MITRE coverage audit for a rule.
    
    Returns:
        Dictionary with coverage_json, gaps_json, overlap_json, confidence
    """
    tech_id = None
    # Try to get MITRE technique from use case
    if rule.use_case and rule.use_case.mitre_claimed:
        tech_ids = rule.use_case.mitre_claimed
        if tech_ids and len(tech_ids) > 0:
            tech_id = tech_ids[0]  # Use first claimed technique
    
    coverage_json = {}
    gaps_json = []
    overlap_json = {}
    confidence = 0.0
    
    if tech_id:
        # Get MITRE details
        mitre_details = mitre_engine.get_technique_details(tech_id)
        
        if mitre_details:
            # Check platform coverage
            user_platforms = [rule.platform] if rule.platform else []
            missing_platforms = mitre_engine.compare_platforms(tech_id, user_platforms)
            
            coverage_json = {
                "technique_id": tech_id,
                "technique_name": mitre_details.get("name", ""),
                "claimed_platforms": mitre_details.get("platforms", []),
                "user_platform": rule.platform,
                "missing_platforms": missing_platforms
            }
            
            gaps_json = [
                {
                    "type": "platform_gap",
                    "platform": platform,
                    "severity": "medium"
                }
                for platform in missing_platforms
            ]
            
            # Calculate confidence (simple: 1.0 if no gaps, 0.7 if gaps)
            confidence = 1.0 if not missing_platforms else 0.7
    
    # Store result
    result = OfflineAuditRepository.create(
        db,
        use_case_id=rule.use_case_id,
        rule_id=rule.id,
        rule_version=rule.version,
        coverage_json=coverage_json,
        gaps_json=gaps_json,
        overlap_json=overlap_json,
        confidence=confidence
    )
    emit_audit_completed(rule.id, rule.rule_name, result.id, confidence, kind="offline")

    return {
        "id": result.id,
        "coverage_json": coverage_json,
        "gaps_json": gaps_json,
        "overlap_json": overlap_json,
        "confidence": confidence,
        "run_at": result.run_at
    }

