"""
Remediation Engine API routes.

POST   /remediation/plans                     → create plan from incident (AI)
GET    /remediation/plans/{plan_id}           → get plan + consent payload
POST   /remediation/plans/{plan_id}/approve   → approve + create execution
POST   /remediation/plans/{plan_id}/reject    → reject plan
POST   /remediation/executions/{exec_id}/run  → start execution (background)
GET    /remediation/executions/{exec_id}      → get execution status
POST   /remediation/executions/{exec_id}/rollback → manual rollback
WS     /remediation/executions/{exec_id}/ws  → real-time execution stream
"""
import asyncio
import json
import uuid
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.engine.remediation_engine import RemediationEngine

router = APIRouter(prefix="/remediation", tags=["remediation"])


# ── Dependency helpers ────────────────────────────────────────────────────────

async def get_redis(request: Request) -> Redis:
    return request.app.state.redis


def get_engine(
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[Redis, Depends(get_redis)],
) -> RemediationEngine:
    return RemediationEngine(db, redis)


# ── Request/Response schemas ──────────────────────────────────────────────────

class CreatePlanRequest(BaseModel):
    incident_id: uuid.UUID
    tenant_id: uuid.UUID


class ApproveRequest(BaseModel):
    tenant_id: uuid.UUID
    actor: str
    notes: str | None = None
    excluded_action_ids: list[str] = []


class RejectRequest(BaseModel):
    tenant_id: uuid.UUID
    actor: str
    notes: str | None = None


class RollbackRequest(BaseModel):
    actor: str


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/plans")
async def create_plan(
    body: CreatePlanRequest,
    engine: Annotated[RemediationEngine, Depends(get_engine)],
):
    """
    AI generates a remediation plan for the given incident.
    Returns the full plan including all actions and impact assessment.
    """
    try:
        plan = await engine.create_plan(body.incident_id, body.tenant_id)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    return {
        "plan_id": str(plan.id),
        "status": plan.status,
        "title": plan.title,
        "overall_impact": plan.overall_impact,
        "ai_confidence": plan.ai_confidence,
        "estimated_duration_seconds": plan.estimated_duration_seconds,
        "actions_count": len(plan.actions),
    }


@router.get("/plans/{plan_id}/consent")
async def get_consent_payload(
    plan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    engine: Annotated[RemediationEngine, Depends(get_engine)],
):
    """
    Returns the full consent payload — what the user sees before approving.
    Includes all actions, impact summary, warnings, and AI analysis.
    """
    try:
        return await engine.get_consent_payload(plan_id, tenant_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/plans/{plan_id}/approve")
async def approve_plan(
    plan_id: uuid.UUID,
    body: ApproveRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    engine: Annotated[RemediationEngine, Depends(get_engine)],
):
    """
    User approves the plan. Creates an execution and starts it in background.
    Returns execution_id immediately — client subscribes to WebSocket for progress.
    """
    try:
        execution = await engine.approve(
            plan_id=plan_id,
            tenant_id=body.tenant_id,
            actor=body.actor,
            notes=body.notes,
            excluded_action_ids=body.excluded_action_ids,
            actor_ip=request.client.host if request.client else None,
            actor_ua=request.headers.get("user-agent"),
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    # Start execution in background — don't block the HTTP response
    background_tasks.add_task(engine.execute, execution.id, body.tenant_id)

    return {
        "execution_id": str(execution.id),
        "status": execution.status,
        "message": "Execution started. Subscribe to WebSocket for real-time updates.",
        "ws_url": f"/remediation/executions/{execution.id}/ws",
    }


@router.post("/plans/{plan_id}/reject")
async def reject_plan(
    plan_id: uuid.UUID,
    body: RejectRequest,
    engine: Annotated[RemediationEngine, Depends(get_engine)],
):
    try:
        await engine.reject(plan_id, body.tenant_id, body.actor, body.notes)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return {"status": "rejected"}


@router.get("/executions/{execution_id}")
async def get_execution_status(
    execution_id: uuid.UUID,
    engine: Annotated[RemediationEngine, Depends(get_engine)],
):
    """Poll-based fallback for execution status (WebSocket preferred)."""
    try:
        execution = await engine._load_execution(execution_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return {
        "execution_id": str(execution.id),
        "status": execution.status,
        "actions_total": execution.actions_total,
        "actions_completed": execution.actions_completed,
        "actions_failed": execution.actions_failed,
        "started_at": execution.started_at,
        "completed_at": execution.completed_at,
        "summary": execution.summary,
        "error": execution.error,
        "rollback_triggered": execution.rollback_triggered,
        "action_results": [
            {
                "action": r.action.title,
                "status": r.status,
                "duration_ms": r.duration_ms,
                "error": r.error,
                "rolled_back": r.rolled_back,
            }
            for r in execution.action_results
        ],
    }


@router.post("/executions/{execution_id}/rollback")
async def rollback_execution(
    execution_id: uuid.UUID,
    body: RollbackRequest,
    background_tasks: BackgroundTasks,
    engine: Annotated[RemediationEngine, Depends(get_engine)],
):
    """Manually trigger rollback on a completed or failed execution."""
    background_tasks.add_task(engine.rollback, execution_id, body.actor)
    return {
        "message": "Rollback started.",
        "ws_url": f"/remediation/executions/{execution_id}/ws",
    }


# ── WebSocket — real-time execution stream ────────────────────────────────────

@router.websocket("/executions/{execution_id}/ws")
async def execution_websocket(
    websocket: WebSocket,
    execution_id: uuid.UUID,
    redis: Annotated[Redis, Depends(get_redis)],
):
    """
    Subscribe to real-time execution events.
    The engine publishes JSON events to Redis pub/sub;
    this WebSocket forwards them to the browser.

    Event types:
      started | action_started | action_success | action_failed |
      action_skipped | completed | rollback_started | rollback_action |
      rollback_completed
    """
    await websocket.accept()
    channel = f"fw:execution:{execution_id}"

    pubsub = redis.pubsub()
    await pubsub.subscribe(channel)

    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                data = message["data"]
                if isinstance(data, bytes):
                    data = data.decode()
                await websocket.send_text(data)

                # Close WS when execution is done
                try:
                    event = json.loads(data)
                    if event.get("event") in ("completed", "rollback_completed"):
                        break
                except json.JSONDecodeError:
                    pass

    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.aclose()
        await websocket.close()
