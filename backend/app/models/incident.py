import uuid
from sqlalchemy import String, Text, JSON, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, UUIDMixin, TimestampMixin


class Incident(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "incidents"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False, index=True
    )

    # Human-readable title: "PowerShell execution chain on PC-CONTADURIA-01"
    title: Mapped[str] = mapped_column(String(500), nullable=False)

    # Severity: critical, high, medium, low, informational
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")

    # Status: open, in_remediation, resolved, false_positive
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="open")

    # Affected assets
    affected_endpoint: Mapped[str | None] = mapped_column(String(200))
    affected_user: Mapped[str | None] = mapped_column(String(200))
    affected_ip: Mapped[str | None] = mapped_column(String(45))

    # Raw detection data (from agent, SIEM, manual input, etc.)
    raw_data: Mapped[dict] = mapped_column(JSON, default=dict)

    # Source: agent, manual, integration, api
    source: Mapped[str] = mapped_column(String(50), default="manual")

    # Remediation plan linked to this incident (if any)
    remediation_plans: Mapped[list["RemediationPlan"]] = relationship(  # noqa: F821
        "RemediationPlan", back_populates="incident", lazy="select"
    )
