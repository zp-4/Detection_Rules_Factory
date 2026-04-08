"""SQLAlchemy models for Use Case Factory."""
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, ForeignKey, Float, Boolean, Index
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()


class UseCase(Base):
    """Use Case model."""
    __tablename__ = "use_cases"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    objective = Column(Text)
    status = Column(String(50), default="draft", index=True)  # draft, review, approved, deprecated
    
    # JSON fields for flexible data
    technologies = Column(JSON)  # List of technologies
    log_sources = Column(JSON)  # List of log sources
    mitre_claimed = Column(JSON)  # List of MITRE technique IDs
    owners = Column(JSON)  # List of owner usernames
    reviewers = Column(JSON)  # List of reviewer usernames
    tags = Column(JSON)  # List of tags
    
    severity = Column(String(50))  # low, medium, high, critical
    false_positives = Column(Text)  # Guidance on false positives
    tuning_guidance = Column(Text)
    
    version = Column(Integer, default=1)
    # Review queue (use case in status=review)
    review_priority = Column(Integer, default=3)  # 1 = highest
    review_sla_days = Column(Integer, nullable=True)
    review_assignee = Column(String(100), nullable=True)
    review_started_at = Column(DateTime, nullable=True)
    review_due_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    rules = relationship("RuleImplementation", back_populates="use_case", cascade="all, delete-orphan")
    offline_audits = relationship("OfflineAuditResult", back_populates="use_case")
    ai_audits = relationship("AiAuditResult", back_populates="use_case")
    comments = relationship("Comment", back_populates="use_case", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index('idx_usecase_status', 'status'),
        Index('idx_usecase_name', 'name'),
    )


class RuleImplementation(Base):
    """Rule Implementation model."""
    __tablename__ = "rule_implementations"
    
    id = Column(Integer, primary_key=True, index=True)
    use_case_id = Column(Integer, ForeignKey("use_cases.id"), nullable=True, index=True)  # Made optional
    platform = Column(String(100), nullable=False, index=True)
    rule_name = Column(String(255), nullable=False)
    rule_text = Column(Text, nullable=False)
    rule_format = Column(String(50))  # splunk, sigma, kql, etc.
    rule_hash = Column(String(64), nullable=False, index=True)  # SHA256 hash
    tags = Column(JSON)  # List of tags for filtering
    mitre_technique_id = Column(String(50), index=True)  # MITRE technique ID (primary/legacy)
    mitre_technique_ids = Column(JSON)  # List of MITRE technique IDs (for multi-mapping)
    last_audit_results = Column(JSON)  # Last audit results: gap_analysis, improvement_suggestion, status
    last_mapping_analysis = Column(JSON)  # Last mapping analysis results
    enabled = Column(Boolean, default=True, index=True)  # Whether the rule is enabled/active
    version = Column(Integer, default=1)
    # External ITSM tickets: list of {system, key?, url?}
    ticket_refs = Column(JSON, nullable=True)
    # production | staging | test | pilot | paused | retired
    operational_status = Column(String(32), default="production", index=True)
    # FP handling, validation, escalation, contacts — JSON object
    playbook = Column(JSON, nullable=True)
    # CTI traceability: [{ "cti_entry_id": int, "note": str, "linked_at": str }]
    cti_refs = Column(JSON, nullable=True)
    # Soft-archive deprecated rules (hidden from default catalogue)
    archived_at = Column(DateTime, nullable=True, index=True)
    archived_by = Column(String(100), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    use_case = relationship("UseCase", back_populates="rules")
    offline_audits = relationship("OfflineAuditResult", back_populates="rule")
    ai_audits = relationship("AiAuditResult", back_populates="rule")
    
    __table_args__ = (
        Index('idx_rule_hash', 'rule_hash'),
        Index('idx_rule_usecase', 'use_case_id'),
    )


class OfflineAuditResult(Base):
    """Offline audit result (MITRE coverage check)."""
    __tablename__ = "offline_audit_results"
    
    id = Column(Integer, primary_key=True, index=True)
    use_case_id = Column(Integer, ForeignKey("use_cases.id"), nullable=False, index=True)
    rule_id = Column(Integer, ForeignKey("rule_implementations.id"), nullable=False, index=True)
    rule_version = Column(Integer, nullable=False)
    
    run_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # JSON results
    coverage_json = Column(JSON)  # MITRE coverage details
    gaps_json = Column(JSON)  # Identified gaps
    overlap_json = Column(JSON)  # Overlap with other rules
    confidence = Column(Float)  # Confidence score 0-1
    
    # Relationships
    use_case = relationship("UseCase", back_populates="offline_audits")
    rule = relationship("RuleImplementation", back_populates="offline_audits")
    
    __table_args__ = (
        Index('idx_offline_rule_version', 'rule_id', 'rule_version'),
    )


class AiAuditResult(Base):
    """AI audit result."""
    __tablename__ = "ai_audit_results"
    
    id = Column(Integer, primary_key=True, index=True)
    use_case_id = Column(Integer, ForeignKey("use_cases.id"), nullable=False, index=True)
    rule_id = Column(Integer, ForeignKey("rule_implementations.id"), nullable=False, index=True)
    rule_version = Column(Integer, nullable=False)
    rule_hash = Column(String(64), nullable=False, index=True)  # For duplicate detection
    
    run_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Justification
    justification_reason = Column(String(100))  # new_rule, major_change, periodic_review, etc.
    justification_note = Column(Text)
    
    # Results
    inferred_mitre_json = Column(JSON)  # MITRE techniques inferred by AI
    mismatch_json = Column(JSON)  # Mismatches with claimed MITRE
    recommendations_json = Column(JSON)  # AI recommendations
    confidence = Column(Float)  # Confidence score 0-1
    
    # Cost tracking
    model_info = Column(String(100))  # Model name/version
    token_usage = Column(Integer)  # Tokens used
    cost_estimate = Column(Float)  # Estimated cost in USD
    
    # Relationships
    use_case = relationship("UseCase", back_populates="ai_audits")
    rule = relationship("RuleImplementation", back_populates="ai_audits")
    
    __table_args__ = (
        Index('idx_ai_rule_hash_version', 'rule_hash', 'rule_version'),
        Index('idx_ai_run_at', 'run_at'),
    )


class CoverageSnapshot(Base):
    """MITRE coverage snapshot."""
    __tablename__ = "coverage_snapshots"
    
    id = Column(Integer, primary_key=True, index=True)
    scope = Column(String(100))  # all, team, use_case_group
    run_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    mitre_matrix_json = Column(JSON)  # Full MITRE matrix coverage
    coverage_percent = Column(Float)  # Overall coverage percentage
    critical_gaps_json = Column(JSON)  # Critical gaps identified
    
    __table_args__ = (
        Index('idx_snapshot_scope_run', 'scope', 'run_at'),
    )


class DecisionLog(Base):
    """Decision log for status changes."""
    __tablename__ = "decision_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    entity_type = Column(String(50), nullable=False)  # use_case, rule, etc.
    entity_id = Column(Integer, nullable=False, index=True)
    from_status = Column(String(50))
    to_status = Column(String(50), nullable=False)
    decided_by = Column(String(100), nullable=False)
    decided_at = Column(DateTime, default=datetime.utcnow, index=True)
    reason = Column(Text)
    
    __table_args__ = (
        Index('idx_decision_entity', 'entity_type', 'entity_id'),
    )


class CtiLibraryEntry(Base):
    """Reusable CTI source metadata (URL, pasted excerpt, file excerpt)."""

    __tablename__ = "cti_library_entries"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(512), nullable=False, index=True)
    # url | paste | file_excerpt
    source_kind = Column(String(32), nullable=False, index=True)
    url = Column(String(2048), nullable=True)
    excerpt_text = Column(Text, nullable=True)
    # vendor, report_type, published_at, original_filename, etc.
    source_metadata = Column("metadata", JSON, nullable=True)
    tags = Column(JSON, nullable=True)
    created_by = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Comment(Base):
    """Comments on entities."""
    __tablename__ = "comments"
    
    id = Column(Integer, primary_key=True, index=True)
    entity_type = Column(String(50), nullable=False)  # use_case, rule, audit, etc.
    entity_id = Column(Integer, nullable=False, index=True)
    use_case_id = Column(Integer, ForeignKey("use_cases.id"), nullable=True, index=True)
    
    author = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    body = Column(Text, nullable=False)
    mentions = Column(JSON, nullable=True)  # list of usernames from @mentions

    # Relationships
    use_case = relationship("UseCase", back_populates="comments")
    
    __table_args__ = (
        Index('idx_comment_entity', 'entity_type', 'entity_id'),
    )


class UserNotification(Base):
    """In-app notifications (e.g. @mentions on comments)."""

    __tablename__ = "user_notifications"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), nullable=False, index=True)
    message = Column(Text, nullable=False)
    read_at = Column(DateTime, nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    entity_type = Column(String(50), nullable=True)
    entity_id = Column(Integer, nullable=True)
    comment_id = Column(Integer, nullable=True)

    __table_args__ = (Index("idx_notif_user_unread", "username", "read_at"),)


class QuotaUsage(Base):
    """Quota usage tracking."""
    __tablename__ = "quota_usage"
    
    id = Column(Integer, primary_key=True, index=True)
    period_yyyymm = Column(String(7), nullable=False, index=True)  # Format: YYYY-MM
    team = Column(String(100), nullable=False, index=True)
    runs_used = Column(Integer, default=0)
    runs_limit = Column(Integer, default=10)  # Default limit
    
    __table_args__ = (
        Index('idx_quota_period_team', 'period_yyyymm', 'team', unique=True),
    )


class AiLock(Base):
    """Lock table for preventing concurrent AI runs."""
    __tablename__ = "ai_locks"
    
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(Integer, nullable=False, index=True)
    rule_hash = Column(String(64), nullable=False, index=True)
    locked_by = Column(String(100))
    locked_at = Column(DateTime, default=datetime.utcnow, index=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    status = Column(String(50), default="RUNNING")  # RUNNING, COMPLETED, FAILED
    
    __table_args__ = (
        Index('idx_lock_rule_hash', 'rule_hash'),
        Index('idx_lock_expires', 'expires_at'),
    )


class MappingReview(Base):
    """Mapping review history for MITRE technique mapping changes."""
    __tablename__ = "mapping_reviews"
    
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(Integer, ForeignKey("rule_implementations.id"), nullable=False, index=True)
    
    reviewed_at = Column(DateTime, default=datetime.utcnow, index=True)
    reviewed_by = Column(String(100), nullable=False)  # Username
    
    # Previous mapping
    previous_technique_id = Column(String(50))  # Previous MITRE technique ID
    previous_technique_name = Column(String(255))
    
    # New mapping
    action_type = Column(String(50), nullable=False)  # "add", "replace", "remove", "multi-mapping"
    new_technique_id = Column(String(50))  # New MITRE technique ID
    new_technique_name = Column(String(255))
    additional_techniques = Column(JSON)  # For multi-mapping: [{"technique_id": "T...", "technique_name": "..."}]
    
    # Review details
    ai_analysis = Column(JSON)  # Full AI analysis result
    recommendation = Column(Text)  # AI recommendation
    reviewer_notes = Column(Text)  # Optional notes from reviewer
    
    # Relationships
    rule = relationship("RuleImplementation")
    
    __table_args__ = (
        Index('idx_mapping_rule_id', 'rule_id'),
        Index('idx_mapping_reviewed_at', 'reviewed_at'),
    )


class RuleChangeLog(Base):
    """Comprehensive audit log for all rule changes - enables rollback."""
    __tablename__ = "rule_change_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(Integer, ForeignKey("rule_implementations.id"), nullable=True, index=True)  # Nullable for deleted rules
    
    # Change metadata
    changed_at = Column(DateTime, default=datetime.utcnow, index=True)
    changed_by = Column(String(100), nullable=False)  # Username who made the change
    
    # Action type
    action = Column(String(50), nullable=False, index=True)  # "create", "update", "delete", "enable", "disable"
    
    # Snapshot before change (for rollback)
    previous_state = Column(JSON)  # Full rule state before change
    
    # Snapshot after change
    new_state = Column(JSON)  # Full rule state after change
    
    # Specific field changes (for quick review)
    changed_fields = Column(JSON)  # {"field_name": {"old": "...", "new": "..."}}
    
    # Optional reason/notes
    reason = Column(Text)
    
    # Rollback tracking
    is_rollback = Column(Boolean, default=False)  # True if this change was a rollback
    rollback_of_id = Column(Integer, ForeignKey("rule_change_logs.id"), nullable=True)  # ID of the change being rolled back
    
    # Relationships
    rule = relationship("RuleImplementation", foreign_keys=[rule_id])
    
    __table_args__ = (
        Index('idx_changelog_rule_id', 'rule_id'),
        Index('idx_changelog_changed_at', 'changed_at'),
        Index('idx_changelog_action', 'action'),
        Index('idx_changelog_changed_by', 'changed_by'),
    )