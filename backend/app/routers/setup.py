"""
First-run setup wizard.

GET  /api/setup/status   → {"complete": bool}
POST /api/setup/complete → creates first tenant, returns tenant_id
"""
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from app.database import get_db
from app.models.tenant import Tenant

router = APIRouter(prefix="/setup", tags=["setup"])


@router.get("/status")
async def setup_status(db: AsyncSession = Depends(get_db)):
    count = await db.scalar(select(func.count()).select_from(Tenant))
    return {"complete": count > 0}


class SetupRequest(BaseModel):
    org_name: str
    anthropic_api_key: str | None = None


@router.post("/complete")
async def complete_setup(body: SetupRequest, db: AsyncSession = Depends(get_db)):
    count = await db.scalar(select(func.count()).select_from(Tenant))
    if count > 0:
        raise HTTPException(status_code=409, detail="Setup already completed.")

    if not body.org_name.strip():
        raise HTTPException(status_code=422, detail="Organization name is required.")

    import re
    slug = re.sub(r"[^a-z0-9]+", "-", body.org_name.lower()).strip("-") or "org"

    tenant = Tenant(
        name=body.org_name.strip(),
        slug=slug,
        autonomous_remediation=False,
        integrations={},
    )
    db.add(tenant)
    await db.commit()
    await db.refresh(tenant)

    # If API key provided here, store it (runtime override)
    if body.anthropic_api_key:
        import os
        os.environ["ANTHROPIC_API_KEY"] = body.anthropic_api_key

    return {
        "tenant_id": str(tenant.id),
        "tenant_name": tenant.name,
        "message": "Setup complete. Welcome to Firewatch EDR.",
    }
