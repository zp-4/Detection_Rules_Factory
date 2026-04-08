"""Repository pattern for database operations."""
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc
from datetime import datetime, timedelta

from db.models import (
    UseCase, RuleImplementation, OfflineAuditResult,
    AiAuditResult, CoverageSnapshot, DecisionLog,
    Comment, QuotaUsage, AiLock, RuleChangeLog
)


# ========== UseCase Repository ==========

class UseCaseRepository:
    """Repository for UseCase operations."""
    
    @staticmethod
    def create(db: Session, **kwargs) -> UseCase:
        """Create a new use case."""
        use_case = UseCase(**kwargs)
        db.add(use_case)
        db.commit()
        db.refresh(use_case)
        return use_case
    
    @staticmethod
    def get_by_id(db: Session, use_case_id: int) -> Optional[UseCase]:
        """Get use case by ID."""
        return db.query(UseCase).filter(UseCase.id == use_case_id).first()
    
    @staticmethod
    def list_all(
        db: Session,
        skip: int = 0,
        limit: int = 100,
        search: Optional[str] = None,
        status: Optional[str] = None,
        technology: Optional[str] = None,
        mitre_technique: Optional[str] = None
    ) -> List[UseCase]:
        """List use cases with filters."""
        query = db.query(UseCase)
        
        if search:
            query = query.filter(
                or_(
                    UseCase.name.ilike(f"%{search}%"),
                    UseCase.description.ilike(f"%{search}%")
                )
            )
        
        if status:
            query = query.filter(UseCase.status == status)
        
        if technology:
            # JSON contains check (SQLite specific)
            query = query.filter(UseCase.technologies.contains([technology]))
        
        if mitre_technique:
            query = query.filter(UseCase.mitre_claimed.contains([mitre_technique]))
        
        return query.order_by(desc(UseCase.updated_at)).offset(skip).limit(limit).all()
    
    @staticmethod
    def update(db: Session, use_case_id: int, **kwargs) -> Optional[UseCase]:
        """Update use case."""
        use_case = UseCaseRepository.get_by_id(db, use_case_id)
        if not use_case:
            return None
        
        for key, value in kwargs.items():
            if hasattr(use_case, key):
                setattr(use_case, key, value)
        
        use_case.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(use_case)
        return use_case
    
    @staticmethod
    def delete(db: Session, use_case_id: int) -> bool:
        """Delete use case."""
        use_case = UseCaseRepository.get_by_id(db, use_case_id)
        if not use_case:
            return False
        db.delete(use_case)
        db.commit()
        return True


# ========== RuleImplementation Repository ==========

class RuleRepository:
    """Repository for RuleImplementation operations."""
    
    @staticmethod
    def create(db: Session, **kwargs) -> RuleImplementation:
        """Create a new rule."""
        rule = RuleImplementation(**kwargs)
        db.add(rule)
        db.commit()
        db.refresh(rule)
        return rule
    
    @staticmethod
    def get_by_id(db: Session, rule_id: int) -> Optional[RuleImplementation]:
        """Get rule by ID."""
        return db.query(RuleImplementation).filter(RuleImplementation.id == rule_id).first()
    
    @staticmethod
    def get_by_use_case(db: Session, use_case_id: int) -> List[RuleImplementation]:
        """Get all rules for a use case."""
        return db.query(RuleImplementation).filter(
            RuleImplementation.use_case_id == use_case_id
        ).order_by(desc(RuleImplementation.created_at)).all()
    
    @staticmethod
    def get_by_hash(db: Session, rule_hash: str) -> Optional[RuleImplementation]:
        """Get rule by hash."""
        return db.query(RuleImplementation).filter(
            RuleImplementation.rule_hash == rule_hash
        ).first()
    
    @staticmethod
    def update(db: Session, rule_id: int, **kwargs) -> Optional[RuleImplementation]:
        """Update rule."""
        rule = RuleRepository.get_by_id(db, rule_id)
        if not rule:
            return None
        
        for key, value in kwargs.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
        
        rule.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(rule)
        return rule
    
    @staticmethod
    def delete(db: Session, rule_id: int) -> bool:
        """Delete rule."""
        rule = RuleRepository.get_by_id(db, rule_id)
        if not rule:
            return False
        db.delete(rule)
        db.commit()
        return True


# ========== Audit Results Repositories ==========

class OfflineAuditRepository:
    """Repository for OfflineAuditResult operations."""
    
    @staticmethod
    def create(db: Session, **kwargs) -> OfflineAuditResult:
        """Create audit result."""
        result = OfflineAuditResult(**kwargs)
        db.add(result)
        db.commit()
        db.refresh(result)
        return result
    
    @staticmethod
    def get_latest_for_rule(
        db: Session,
        rule_id: int,
        rule_version: Optional[int] = None
    ) -> Optional[OfflineAuditResult]:
        """Get latest audit result for a rule."""
        query = db.query(OfflineAuditResult).filter(
            OfflineAuditResult.rule_id == rule_id
        )
        
        if rule_version:
            query = query.filter(OfflineAuditResult.rule_version == rule_version)
        
        return query.order_by(desc(OfflineAuditResult.run_at)).first()
    
    @staticmethod
    def get_for_use_case(db: Session, use_case_id: int) -> List[OfflineAuditResult]:
        """Get all audits for a use case."""
        return db.query(OfflineAuditResult).filter(
            OfflineAuditResult.use_case_id == use_case_id
        ).order_by(desc(OfflineAuditResult.run_at)).all()


class AiAuditRepository:
    """Repository for AiAuditResult operations."""
    
    @staticmethod
    def create(db: Session, **kwargs) -> AiAuditResult:
        """Create AI audit result."""
        result = AiAuditResult(**kwargs)
        db.add(result)
        db.commit()
        db.refresh(result)
        return result
    
    @staticmethod
    def get_recent_for_rule_hash(
        db: Session,
        rule_hash: str,
        rule_version: int,
        days: int = 30
    ) -> Optional[AiAuditResult]:
        """Get recent AI audit result for a rule hash (for duplicate detection)."""
        cutoff = datetime.utcnow() - timedelta(days=days)
        return db.query(AiAuditResult).filter(
            AiAuditResult.rule_hash == rule_hash,
            AiAuditResult.rule_version == rule_version,
            AiAuditResult.run_at >= cutoff
        ).order_by(desc(AiAuditResult.run_at)).first()
    
    @staticmethod
    def get_for_rule(db: Session, rule_id: int) -> List[AiAuditResult]:
        """Get all AI audits for a rule."""
        return db.query(AiAuditResult).filter(
            AiAuditResult.rule_id == rule_id
        ).order_by(desc(AiAuditResult.run_at)).all()
    
    @staticmethod
    def get_for_use_case(db: Session, use_case_id: int) -> List[AiAuditResult]:
        """Get all AI audits for a use case."""
        return db.query(AiAuditResult).filter(
            AiAuditResult.use_case_id == use_case_id
        ).order_by(desc(AiAuditResult.run_at)).all()


# ========== Other Repositories ==========

class CommentRepository:
    """Repository for Comment operations."""
    
    @staticmethod
    def create(db: Session, **kwargs) -> Comment:
        """Create comment."""
        comment = Comment(**kwargs)
        db.add(comment)
        db.commit()
        db.refresh(comment)
        return comment
    
    @staticmethod
    def get_for_entity(
        db: Session,
        entity_type: str,
        entity_id: int
    ) -> List[Comment]:
        """Get comments for an entity."""
        return db.query(Comment).filter(
            Comment.entity_type == entity_type,
            Comment.entity_id == entity_id
        ).order_by(Comment.created_at).all()


class QuotaRepository:
    """Repository for QuotaUsage operations."""
    
    @staticmethod
    def get_or_create(
        db: Session,
        period: str,
        team: str,
        default_limit: int = 10
    ) -> QuotaUsage:
        """Get or create quota usage for period/team."""
        quota = db.query(QuotaUsage).filter(
            QuotaUsage.period_yyyymm == period,
            QuotaUsage.team == team
        ).first()
        
        if not quota:
            quota = QuotaUsage(
                period_yyyymm=period,
                team=team,
                runs_used=0,
                runs_limit=default_limit
            )
            db.add(quota)
            db.commit()
            db.refresh(quota)
        
        return quota
    
    @staticmethod
    def increment_usage(db: Session, period: str, team: str) -> bool:
        """Increment quota usage."""
        quota = QuotaRepository.get_or_create(db, period, team)
        if quota.runs_used >= quota.runs_limit:
            return False  # Quota exceeded
        
        quota.runs_used += 1
        db.commit()
        return True
    
    @staticmethod
    def set_limit(db: Session, period: str, team: str, limit: int):
        """Set quota limit."""
        quota = QuotaRepository.get_or_create(db, period, team)
        quota.runs_limit = limit
        db.commit()


# ========== Rule Change Log Repository ==========

class RuleChangeLogRepository:
    """Repository for RuleChangeLog operations - audit trail and rollback."""
    
    @staticmethod
    def _rule_to_dict(rule: RuleImplementation) -> Dict[str, Any]:
        """Convert a rule to a dictionary for storage."""
        if not rule:
            return {}
        return {
            "id": rule.id,
            "use_case_id": rule.use_case_id,
            "platform": rule.platform,
            "rule_name": rule.rule_name,
            "rule_text": rule.rule_text,
            "rule_format": rule.rule_format,
            "rule_hash": rule.rule_hash,
            "tags": rule.tags,
            "mitre_technique_id": rule.mitre_technique_id,
            "mitre_technique_ids": rule.mitre_technique_ids,
            "last_audit_results": rule.last_audit_results,
            "last_mapping_analysis": rule.last_mapping_analysis,
            "enabled": rule.enabled,
            "version": rule.version,
            "ticket_refs": getattr(rule, "ticket_refs", None),
            "operational_status": getattr(rule, "operational_status", None) or "production",
            "playbook": getattr(rule, "playbook", None),
            "created_at": rule.created_at.isoformat() if rule.created_at else None,
            "updated_at": rule.updated_at.isoformat() if rule.updated_at else None,
        }
    
    @staticmethod
    def log_create(
        db: Session,
        rule: RuleImplementation,
        changed_by: str,
        reason: Optional[str] = None
    ) -> RuleChangeLog:
        """Log a rule creation."""
        new_state = RuleChangeLogRepository._rule_to_dict(rule)
        log_entry = RuleChangeLog(
            rule_id=rule.id,
            changed_by=changed_by,
            action="create",
            previous_state=None,
            new_state=new_state,
            changed_fields={"all": {"old": None, "new": "created"}},
            reason=reason
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)
        return log_entry
    
    @staticmethod
    def log_update(
        db: Session,
        rule: RuleImplementation,
        previous_state: Dict[str, Any],
        changed_by: str,
        reason: Optional[str] = None
    ) -> RuleChangeLog:
        """Log a rule update with field-level changes."""
        new_state = RuleChangeLogRepository._rule_to_dict(rule)

        # Calculate changed fields
        changed_fields: Dict[str, Any] = {}
        for key in new_state:
            old_val = previous_state.get(key)
            new_val = new_state.get(key)
            if old_val != new_val:
                changed_fields[key] = {"old": old_val, "new": new_val}

        # Bump business version when meaningful fields change (not cache-only)
        meta_only = {"updated_at", "last_audit_results", "last_mapping_analysis"}
        if any(k not in meta_only for k in changed_fields):
            rule.version = (rule.version or 1) + 1
            db.commit()
            db.refresh(rule)
            new_state = RuleChangeLogRepository._rule_to_dict(rule)
            changed_fields = {}
            for key in new_state:
                old_val = previous_state.get(key)
                new_val = new_state.get(key)
                if old_val != new_val:
                    changed_fields[key] = {"old": old_val, "new": new_val}

        log_entry = RuleChangeLog(
            rule_id=rule.id,
            changed_by=changed_by,
            action="update",
            previous_state=previous_state,
            new_state=new_state,
            changed_fields=changed_fields,
            reason=reason
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)
        return log_entry
    
    @staticmethod
    def log_delete(
        db: Session,
        rule: RuleImplementation,
        changed_by: str,
        reason: Optional[str] = None
    ) -> RuleChangeLog:
        """Log a rule deletion (stores full state for potential recovery)."""
        previous_state = RuleChangeLogRepository._rule_to_dict(rule)
        log_entry = RuleChangeLog(
            rule_id=rule.id,
            changed_by=changed_by,
            action="delete",
            previous_state=previous_state,
            new_state=None,
            changed_fields={"all": {"old": "deleted", "new": None}},
            reason=reason
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)
        return log_entry
    
    @staticmethod
    def log_enable_disable(
        db: Session,
        rule: RuleImplementation,
        changed_by: str,
        new_enabled: bool,
        reason: Optional[str] = None
    ) -> RuleChangeLog:
        """Log enable/disable action."""
        previous_state = RuleChangeLogRepository._rule_to_dict(rule)
        action = "enable" if new_enabled else "disable"
        
        log_entry = RuleChangeLog(
            rule_id=rule.id,
            changed_by=changed_by,
            action=action,
            previous_state=previous_state,
            new_state=None,  # Will be filled after actual update
            changed_fields={"enabled": {"old": not new_enabled, "new": new_enabled}},
            reason=reason
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)
        return log_entry
    
    @staticmethod
    def get_rule_history(
        db: Session,
        rule_id: int,
        limit: int = 50
    ) -> List[RuleChangeLog]:
        """Get change history for a specific rule."""
        return db.query(RuleChangeLog).filter(
            RuleChangeLog.rule_id == rule_id
        ).order_by(desc(RuleChangeLog.changed_at)).limit(limit).all()
    
    @staticmethod
    def get_all_changes(
        db: Session,
        skip: int = 0,
        limit: int = 100,
        action: Optional[str] = None,
        changed_by: Optional[str] = None,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None
    ) -> List[RuleChangeLog]:
        """Get all changes with optional filters."""
        query = db.query(RuleChangeLog)
        
        if action:
            query = query.filter(RuleChangeLog.action == action)
        if changed_by:
            query = query.filter(RuleChangeLog.changed_by == changed_by)
        if from_date:
            query = query.filter(RuleChangeLog.changed_at >= from_date)
        if to_date:
            query = query.filter(RuleChangeLog.changed_at <= to_date)
        
        return query.order_by(desc(RuleChangeLog.changed_at)).offset(skip).limit(limit).all()
    
    @staticmethod
    def get_change_by_id(db: Session, log_id: int) -> Optional[RuleChangeLog]:
        """Get a specific change log entry by ID."""
        return db.query(RuleChangeLog).filter(RuleChangeLog.id == log_id).first()
    
    @staticmethod
    def rollback_change(
        db: Session,
        log_id: int,
        rolled_back_by: str,
        reason: Optional[str] = None
    ) -> Optional[RuleImplementation]:
        """
        Rollback a change by restoring the previous state.
        Returns the restored rule or None if rollback failed.
        """
        log_entry = RuleChangeLogRepository.get_change_by_id(db, log_id)
        if not log_entry:
            return None
        
        # For delete actions, we need to restore the rule
        if log_entry.action == "delete":
            if not log_entry.previous_state:
                return None
            
            # Create new rule from previous state
            prev = log_entry.previous_state
            restored_rule = RuleImplementation(
                use_case_id=prev.get("use_case_id"),
                platform=prev.get("platform"),
                rule_name=prev.get("rule_name"),
                rule_text=prev.get("rule_text"),
                rule_format=prev.get("rule_format"),
                rule_hash=prev.get("rule_hash"),
                tags=prev.get("tags"),
                mitre_technique_id=prev.get("mitre_technique_id"),
                mitre_technique_ids=prev.get("mitre_technique_ids"),
                last_audit_results=prev.get("last_audit_results"),
                last_mapping_analysis=prev.get("last_mapping_analysis"),
                enabled=prev.get("enabled", True),
                ticket_refs=prev.get("ticket_refs"),
                operational_status=prev.get("operational_status") or "production",
                playbook=prev.get("playbook"),
                version=(prev.get("version", 1) or 1) + 1
            )
            db.add(restored_rule)
            db.commit()
            db.refresh(restored_rule)
            
            # Log the rollback
            rollback_log = RuleChangeLog(
                rule_id=restored_rule.id,
                changed_by=rolled_back_by,
                action="create",
                previous_state=None,
                new_state=RuleChangeLogRepository._rule_to_dict(restored_rule),
                changed_fields={"all": {"old": None, "new": "restored"}},
                reason=reason or f"Rollback of change #{log_id}",
                is_rollback=True,
                rollback_of_id=log_id
            )
            db.add(rollback_log)
            db.commit()
            
            return restored_rule
        
        # For update actions, restore previous state
        elif log_entry.action in ["update", "enable", "disable"]:
            if not log_entry.previous_state:
                return None
            
            rule = db.query(RuleImplementation).filter(
                RuleImplementation.id == log_entry.rule_id
            ).first()
            
            if not rule:
                return None
            
            # Store current state before rollback
            current_state = RuleChangeLogRepository._rule_to_dict(rule)
            
            # Restore previous state
            prev = log_entry.previous_state
            rule.platform = prev.get("platform")
            rule.rule_name = prev.get("rule_name")
            rule.rule_text = prev.get("rule_text")
            rule.rule_format = prev.get("rule_format")
            rule.rule_hash = prev.get("rule_hash")
            rule.tags = prev.get("tags")
            rule.mitre_technique_id = prev.get("mitre_technique_id")
            rule.mitre_technique_ids = prev.get("mitre_technique_ids")
            rule.last_audit_results = prev.get("last_audit_results")
            rule.last_mapping_analysis = prev.get("last_mapping_analysis")
            rule.enabled = prev.get("enabled", True)
            if hasattr(rule, "ticket_refs"):
                rule.ticket_refs = prev.get("ticket_refs")
            if hasattr(rule, "operational_status"):
                rule.operational_status = prev.get("operational_status") or "production"
            if hasattr(rule, "playbook"):
                rule.playbook = prev.get("playbook")
            rule.version = (rule.version or 1) + 1
            rule.updated_at = datetime.utcnow()
            
            db.commit()
            db.refresh(rule)
            
            # Log the rollback
            rollback_log = RuleChangeLog(
                rule_id=rule.id,
                changed_by=rolled_back_by,
                action="update",
                previous_state=current_state,
                new_state=RuleChangeLogRepository._rule_to_dict(rule),
                changed_fields={"all": {"old": "current", "new": "restored"}},
                reason=reason or f"Rollback of change #{log_id}",
                is_rollback=True,
                rollback_of_id=log_id
            )
            db.add(rollback_log)
            db.commit()
            
            return rule
        
        return None

