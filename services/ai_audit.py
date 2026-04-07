"""AI audit service with cost control."""
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from src.ai_engine import AIEngine
from src.mitre_engine import MitreEngine
from db.repo import AiAuditRepository
from db.models import RuleImplementation
from utils.locking import acquire_ai_lock, release_ai_lock, is_locked
from services.quota import check_quota, consume_quota
from services.auth import get_current_user, get_user_team


def run_ai_audit(
    db: Session,
    rule: RuleImplementation,
    ai_engine: AIEngine,
    mitre_engine: MitreEngine,
    justification_reason: str,
    justification_note: str = "",
    force_rerun: bool = False
) -> Dict[str, Any]:
    """
    Run AI audit with cost control and duplicate detection.
    
    Args:
        db: Database session
        rule: Rule to audit
        ai_engine: AI engine instance
        mitre_engine: MITRE engine instance
        justification_reason: Reason for running AI audit
        justification_note: Optional note
        force_rerun: Force rerun even if recent result exists (admin only)
    
    Returns:
        Dictionary with audit results
    """
    # Check quota
    username = get_current_user()
    team = get_user_team(username)
    if not team:
        raise ValueError("User team not found")
    
    has_quota, used, limit = check_quota(db, team)
    if not has_quota and not force_rerun:
        raise ValueError(f"Quota exceeded: {used}/{limit} runs used this month")
    
    # Check for recent duplicate (unless force rerun)
    if not force_rerun:
        recent_result = AiAuditRepository.get_recent_for_rule_hash(
            db, rule.rule_hash, rule.version, days=30
        )
        if recent_result:
            return {
                "reused": True,
                "result_id": recent_result.id,
                "run_at": recent_result.run_at,
                "inferred_mitre_json": recent_result.inferred_mitre_json,
                "mismatch_json": recent_result.mismatch_json,
                "recommendations_json": recent_result.recommendations_json,
                "confidence": recent_result.confidence
            }
    
    # Check lock
    if is_locked(db, rule.rule_hash):
        raise ValueError("AI analysis already running for this rule")
    
    # Acquire lock
    lock = acquire_ai_lock(db, rule.id, rule.rule_hash, username or "system")
    if not lock:
        raise ValueError("Failed to acquire lock")
    
    try:
        # Consume quota
        if not consume_quota(db, team):
            raise ValueError("Failed to consume quota")
        
        # Get MITRE details
        tech_id = None
        if rule.use_case and rule.use_case.mitre_claimed:
            tech_ids = rule.use_case.mitre_claimed
            if tech_ids and len(tech_ids) > 0:
                tech_id = tech_ids[0]
        
        if not tech_id:
            raise ValueError("No MITRE technique claimed for this use case")
        
        mitre_details = mitre_engine.get_technique_details(tech_id)
        if not mitre_details:
            raise ValueError(f"MITRE technique {tech_id} not found")
        
        # Run AI analysis
        analysis = ai_engine.analyze_coverage(
            tech_id=tech_id,
            technique_name=mitre_details.get("name", ""),
            mitre_detection_desc=mitre_details.get("detection", ""),
            data_components=mitre_details.get("data_components", []),
            mitre_analytics=mitre_details.get("analytics", []),
            user_query=rule.rule_text,
            platform=rule.platform,
            detection_strategies=mitre_details.get("detection_strategies", []),
            data_sources=mitre_details.get("data_sources", []),
            technique_url=mitre_details.get("technique_url", "")
        )
        
        # Extract results
        inferred_mitre = {
            "technique_id": tech_id,
            "technique_name": mitre_details.get("name", ""),
            "satisfies_requirements": analysis.get("satisfies_requirements", False),
            "coverage_score": analysis.get("coverage_score", "Unknown")
        }
        
        mismatch = {
            "has_mismatch": not analysis.get("satisfies_requirements", False),
            "gap_analysis": analysis.get("gap_analysis", ""),
            "claimed_techniques": rule.use_case.mitre_claimed if rule.use_case else []
        }
        
        recommendations = {
            "improvement_suggestion": analysis.get("improvement_suggestion", ""),
            "pseudo_code_recommendation": analysis.get("pseudo_code_recommendation", "")
        }
        
        # Estimate cost (rough estimate: $0.01 per 1K tokens)
        token_usage = 1000  # Placeholder - would need to get from AI engine
        cost_estimate = (token_usage / 1000) * 0.01
        
        # Store result
        result = AiAuditRepository.create(
            db,
            use_case_id=rule.use_case_id,
            rule_id=rule.id,
            rule_version=rule.version,
            rule_hash=rule.rule_hash,
            justification_reason=justification_reason,
            justification_note=justification_note,
            inferred_mitre_json=inferred_mitre,
            mismatch_json=mismatch,
            recommendations_json=recommendations,
            confidence=analysis.get("coverage_score", "Medium") == "High" and 0.9 or 0.7,
            model_info=f"{ai_engine.provider}",
            token_usage=token_usage,
            cost_estimate=cost_estimate
        )
        
        # Release lock
        release_ai_lock(db, lock.id, "COMPLETED")
        
        return {
            "reused": False,
            "result_id": result.id,
            "run_at": result.run_at,
            "inferred_mitre_json": inferred_mitre,
            "mismatch_json": mismatch,
            "recommendations_json": recommendations,
            "confidence": result.confidence,
            "cost_estimate": cost_estimate
        }
    
    except Exception as e:
        # Release lock on error
        release_ai_lock(db, lock.id, "FAILED")
        raise e

