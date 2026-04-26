"""
Demo seeder — creates a demo tenant + incident on first call.
Returns their IDs so the frontend can use them without auth.
"""
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import APIRouter, Depends
from app.database import get_db
from app.models.tenant import Tenant
from app.models.incident import Incident

router = APIRouter(prefix="/demo", tags=["demo"])


@router.get("/state")
async def get_demo_state(db: AsyncSession = Depends(get_db)):
    # Tenant
    result = await db.execute(select(Tenant).where(Tenant.slug == "demo"))
    tenant = result.scalar_one_or_none()
    if not tenant:
        tenant = Tenant(
            name="Geonosis S.A.",
            slug="demo",
            autonomous_remediation=False,
            integrations={
                "mikrotik": {"host": "192.168.88.1", "user": "admin", "password": ""},
                "entra_id": {"tenant_id": "", "client_id": "", "client_secret": ""},
                "teams_webhook": "",
            },
        )
        db.add(tenant)
        await db.flush()

    # Incident
    result = await db.execute(
        select(Incident)
        .where(Incident.tenant_id == tenant.id, Incident.status == "open")
        .limit(1)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        incident = Incident(
            tenant_id=tenant.id,
            title="PowerShell execution chain on PC-CONTADURIA-01",
            severity="critical",
            status="open",
            affected_endpoint="PC-CONTADURIA-01",
            affected_user="maria.gomez",
            affected_ip="185.220.101.47",
            source="agent",
            raw_data={
                "process_chain": "winword.exe → powershell.exe",
                "arguments": "-EncodedCommand JABjAGwAaQBlAG4AdA...",
                "c2_ip": "185.220.101.47",
                "c2_category": "Emotet C2",
                "endpoint_mac": "AA:BB:CC:11:22:33",
                "user_upn": "maria.gomez@geonosis.com",
                "user_entra_id": "user-maria-gomez-demo",
                "mitre_techniques": ["T1059.001", "T1071.001", "T1027"],
                "detection_confidence": 0.94,
            },
        )
        db.add(incident)

    await db.commit()
    return {
        "tenant_id": str(tenant.id),
        "incident_id": str(incident.id),
        "tenant_name": tenant.name,
        "incident_title": incident.title,
        "incident_severity": incident.severity,
    }
