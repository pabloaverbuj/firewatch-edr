import uuid
from datetime import datetime
from sqlalchemy import String, Text, JSON, ForeignKey, Boolean, Integer, Float, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, UUIDMixin, TimestampMixin


# ── ACTION TYPES ──────────────────────────────────────────────────────────────
# Each type maps to a concrete adapter that knows how to execute and rollback it.

class ActionType:
    # Network (MikroTik)
    NETWORK_ISOLATE       = "network_isolate"
    NETWORK_RESTORE       = "network_restore"
    BLOCK_IP              = "block_ip"
    UNBLOCK_IP            = "unblock_ip"
    VLAN_QUARANTINE       = "vlan_quarantine"

    # Identity (Entra ID / AD)
    IDENTITY_BLOCK_USER   = "identity_block_user"
    IDENTITY_UNBLOCK_USER = "identity_unblock_user"
    IDENTITY_REVOKE_SESSIONS = "identity_revoke_sessions"
    IDENTITY_RESET_MFA    = "identity_reset_mfa"
    IDENTITY_FORCE_PASSWORD_RESET = "identity_force_password_reset"

    # Endpoint (agent)
    PROCESS_KILL          = "process_kill"
    FILE_QUARANTINE       = "file_quarantine"
    FILE_DELETE           = "file_delete"
    ROLLBACK_FILES        = "rollback_files"
    FORCE_PATCH           = "force_patch"

    # Notifications
    NOTIFY_TEAMS          = "notify_teams"
    NOTIFY_EMAIL          = "notify_email"

    # Generic
    CUSTOM                = "custom"


# ── IMPACT LEVELS ─────────────────────────────────────────────────────────────

class ImpactLevel:
    INFORMATIONAL = "informational"  # No service disruption
    LOW           = "low"            # Minimal, user unaware
    MEDIUM        = "medium"         # User affected temporarily
    HIGH          = "high"           # Service interruption, user locked out
    CRITICAL      = "critical"       # Full isolation, major disruption


# ── PLAN STATUS ───────────────────────────────────────────────────────────────

class PlanStatus:
    DRAFT             = "draft"
    AWAITING_CONSENT  = "awaiting_consent"
    APPROVED          = "approved"
    REJECTED          = "rejected"
    EXECUTING         = "executing"
    COMPLETED         = "completed"
    FAILED            = "failed"
    ROLLED_BACK       = "rolled_back"


# ── EXECUTION STATUS ──────────────────────────────────────────────────────────

class ExecutionStatus:
    PENDING     = "pending"
    RUNNING     = "running"
    COMPLETED   = "completed"
    FAILED      = "failed"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    CANCELLED   = "cancelled"


# ── MODELS ────────────────────────────────────────────────────────────────────

class RemediationPlan(Base, UUIDMixin, TimestampMixin):
    """
    A plan is a list of actions to take in response to an incident.
    It lives through a consent flow before execution.
    """
    __tablename__ = "remediation_plans"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False, index=True
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=False, index=True
    )

    status: Mapped[str] = mapped_column(String(30), nullable=False, default=PlanStatus.DRAFT)

    # Human-readable summary of what this plan does
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    # AI-generated analysis that led to this plan
    ai_analysis: Mapped[str | None] = mapped_column(Text)
    ai_confidence: Mapped[float | None] = mapped_column(Float)

    # Aggregate impact computed from all actions
    overall_impact: Mapped[str] = mapped_column(String(20), default=ImpactLevel.MEDIUM)
    requires_downtime: Mapped[bool] = mapped_column(Boolean, default=False)
    fully_reversible: Mapped[bool] = mapped_column(Boolean, default=True)
    estimated_duration_seconds: Mapped[int] = mapped_column(Integer, default=0)

    # Structured impact summary shown to user at consent time
    impact_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    # Example:
    # {
    #   "affected_users": ["maria.gomez"],
    #   "affected_endpoints": ["PC-CONTADURIA-01"],
    #   "affected_services": ["M365", "MikroTik"],
    #   "irreversible_actions": ["process_kill", "identity_revoke_sessions"],
    #   "warnings": ["User will lose network access immediately"],
    # }

    # Relationships
    incident: Mapped["Incident"] = relationship("Incident", back_populates="remediation_plans")  # noqa: F821
    actions: Mapped[list["RemediationAction"]] = relationship(
        "RemediationAction", back_populates="plan", order_by="RemediationAction.order", cascade="all, delete-orphan"
    )
    consent: Mapped["ConsentRecord | None"] = relationship(
        "ConsentRecord", back_populates="plan", uselist=False
    )
    executions: Mapped[list["RemediationExecution"]] = relationship(
        "RemediationExecution", back_populates="plan"
    )


class RemediationAction(Base, UUIDMixin, TimestampMixin):
    """
    A single atomic action within a plan.
    Each action knows its type, target, impact, and reversibility.
    """
    __tablename__ = "remediation_actions"

    plan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("remediation_plans.id"), nullable=False, index=True
    )

    # Execution order (lower = first)
    order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # What to do
    action_type: Mapped[str] = mapped_column(String(60), nullable=False)

    # Human-readable description for the consent screen
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    # Target of the action (endpoint name, username, IP, process name, etc.)
    target: Mapped[str | None] = mapped_column(String(300))

    # Adapter-specific parameters (e.g. {"ip": "192.168.1.50", "interface": "ether1"})
    params: Mapped[dict] = mapped_column(JSON, default=dict)

    # Impact of this specific action
    impact_level: Mapped[str] = mapped_column(String(20), default=ImpactLevel.MEDIUM)
    impact_description: Mapped[str | None] = mapped_column(Text)

    # Whether this action can be undone automatically
    reversible: Mapped[bool] = mapped_column(Boolean, default=True)
    # Params needed to roll back (e.g. {"restore_point": "2024-01-01T03:44:00Z"})
    rollback_params: Mapped[dict] = mapped_column(JSON, default=dict)

    # Whether execution of this action can be skipped if user selects partial approval
    optional: Mapped[bool] = mapped_column(Boolean, default=False)
    # Whether this action depends on a previous one succeeding
    depends_on_order: Mapped[int | None] = mapped_column(Integer)

    plan: Mapped["RemediationPlan"] = relationship("RemediationPlan", back_populates="actions")
    result: Mapped["ActionResult | None"] = relationship(
        "ActionResult", back_populates="action", uselist=False
    )


class ConsentRecord(Base, UUIDMixin, TimestampMixin):
    """
    Immutable record of what the user saw and agreed to (or rejected).
    This is the audit-legal evidence that the user was informed.
    """
    __tablename__ = "consent_records"

    plan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("remediation_plans.id"), nullable=False, unique=True
    )

    # Who acted (user ID / email)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)

    # approved | rejected | auto_approved (autonomous mode)
    decision: Mapped[str] = mapped_column(String(20), nullable=False)

    # Optional note from the user ("Approved - ransomware confirmed")
    notes: Mapped[str | None] = mapped_column(Text)

    # Exact snapshot of what was shown to the user when they decided
    # This makes the record tamper-evident
    plan_snapshot: Mapped[dict] = mapped_column(JSON, nullable=False)

    # Which actions were excluded in case of partial approval
    excluded_action_ids: Mapped[list] = mapped_column(JSON, default=list)

    # IP address and user agent for audit trail
    actor_ip: Mapped[str | None] = mapped_column(String(45))
    actor_ua: Mapped[str | None] = mapped_column(String(500))

    plan: Mapped["RemediationPlan"] = relationship("RemediationPlan", back_populates="consent")


class RemediationExecution(Base, UUIDMixin, TimestampMixin):
    """
    A single run of an approved remediation plan.
    Tracks real-time progress and final outcome.
    """
    __tablename__ = "remediation_executions"

    plan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("remediation_plans.id"), nullable=False, index=True
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False, index=True
    )

    status: Mapped[str] = mapped_column(String(30), nullable=False, default=ExecutionStatus.PENDING)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Number of actions completed vs total
    actions_total: Mapped[int] = mapped_column(Integer, default=0)
    actions_completed: Mapped[int] = mapped_column(Integer, default=0)
    actions_failed: Mapped[int] = mapped_column(Integer, default=0)

    # Final summary message
    summary: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)

    # Whether a rollback was triggered on failure
    rollback_triggered: Mapped[bool] = mapped_column(Boolean, default=False)

    plan: Mapped["RemediationPlan"] = relationship("RemediationPlan", back_populates="executions")
    action_results: Mapped[list["ActionResult"]] = relationship(
        "ActionResult", back_populates="execution", order_by="ActionResult.started_at"
    )


class ActionResult(Base, UUIDMixin, TimestampMixin):
    """
    Result of executing a single RemediationAction.
    """
    __tablename__ = "action_results"

    execution_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("remediation_executions.id"), nullable=False, index=True
    )
    action_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("remediation_actions.id"), nullable=False
    )

    # pending | running | success | failed | skipped | rolled_back
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Duration in milliseconds
    duration_ms: Mapped[int | None] = mapped_column(Integer)

    # Adapter output (e.g. {"firewall_rule_id": "...", "mikrotik_response": "..."})
    output: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text)

    # Whether this result was later rolled back
    rolled_back: Mapped[bool] = mapped_column(Boolean, default=False)
    rollback_result: Mapped[dict] = mapped_column(JSON, default=dict)

    execution: Mapped["RemediationExecution"] = relationship(
        "RemediationExecution", back_populates="action_results"
    )
    action: Mapped["RemediationAction"] = relationship(
        "RemediationAction", back_populates="result"
    )
