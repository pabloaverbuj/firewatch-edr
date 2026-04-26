from sqlalchemy import String, Boolean, JSON
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base, UUIDMixin, TimestampMixin


class Tenant(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)

    # Autonomous mode: engine executes without asking each time
    autonomous_remediation: Mapped[bool] = mapped_column(Boolean, default=False)

    # Which integrations are configured for this tenant
    integrations: Mapped[dict] = mapped_column(JSON, default=dict)
    # Example:
    # {
    #   "mikrotik": {"host": "...", "user": "...", "password_encrypted": "..."},
    #   "entra_id": {"tenant_id": "...", "client_id": "...", "client_secret_encrypted": "..."},
    #   "teams_webhook": "https://...",
    # }

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
