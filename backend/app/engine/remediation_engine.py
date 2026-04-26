"""
RemediationEngine — the core of Firewatch.

Flow:
  1. create_plan(incident_id)  →  AI generates plan + impact assessment
  2. get_consent_payload(plan_id)  →  returns what to show the user
  3. approve(plan_id, actor) or reject(plan_id, actor)
  4. execute(plan_id)  →  runs actions, publishes real-time status via Redis
  5. rollback(execution_id)  →  undoes reversible actions on demand or on failure
"""
import asyncio
import json
import uuid
from datetime import datetime, timezone

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.engine import plan_generator
from app.engine.adapters import ADAPTER_REGISTRY
from app.models.incident import Incident
from app.models.remediation import (
    ActionResult,
    ConsentRecord,
    ExecutionStatus,
    ImpactLevel,
    PlanStatus,
    RemediationAction,
    RemediationExecution,
    RemediationPlan,
)
from app.models.tenant import Tenant


# Redis channel prefix for real-time execution updates
_CHANNEL = "fw:execution:{execution_id}"


class RemediationEngine:

    def __init__(self, db: AsyncSession, redis: Redis):
        self.db = db
        self.redis = redis

    # ── 1. CREATE PLAN ────────────────────────────────────────────────────────

    async def create_plan(self, incident_id: uuid.UUID, tenant_id: uuid.UUID) -> RemediationPlan:
        """
        Generate an AI-powered remediation plan for an incident.
        Saves the plan and all actions to DB, returns the plan object.
        """
        incident = await self._require(Incident, incident_id, tenant_id)

        plan_data = await plan_generator.generate_plan(incident)

        plan = RemediationPlan(
            tenant_id=tenant_id,
            incident_id=incident_id,
            status=PlanStatus.DRAFT,
            title=plan_data["title"],
            description=plan_data.get("description"),
            ai_analysis=plan_data.get("ai_analysis"),
            ai_confidence=plan_data.get("ai_confidence"),
            overall_impact=plan_data.get("overall_impact", ImpactLevel.MEDIUM),
            requires_downtime=plan_data.get("requires_downtime", False),
            fully_reversible=plan_data.get("fully_reversible", True),
            estimated_duration_seconds=plan_data.get("estimated_duration_seconds", 0),
        )
        self.db.add(plan)
        await self.db.flush()  # get plan.id before adding actions

        actions = []
        for a in plan_data.get("actions", []):
            action = RemediationAction(
                plan_id=plan.id,
                order=a["order"],
                action_type=a["action_type"],
                title=a["title"],
                description=a.get("description"),
                target=a.get("target"),
                params=a.get("params", {}),
                impact_level=a.get("impact_level", ImpactLevel.MEDIUM),
                impact_description=a.get("impact_description"),
                reversible=a.get("reversible", True),
                rollback_params=a.get("rollback_params", {}),
                optional=a.get("optional", False),
                depends_on_order=a.get("depends_on_order"),
            )
            actions.append(action)
            self.db.add(action)

        plan.impact_summary = _build_impact_summary(plan_data, actions)
        await self.db.commit()
        await self.db.refresh(plan)
        return plan

    # ── 2. CONSENT PAYLOAD ────────────────────────────────────────────────────

    async def get_consent_payload(self, plan_id: uuid.UUID, tenant_id: uuid.UUID) -> dict:
        """
        Return a structured payload that the frontend shows to the user
        before they approve or reject.  This is the key UX of the engine.
        """
        plan = await self._load_plan(plan_id, tenant_id)

        payload = {
            "plan_id": str(plan.id),
            "title": plan.title,
            "description": plan.description,
            "ai_analysis": plan.ai_analysis,
            "ai_confidence": plan.ai_confidence,
            "overall_impact": plan.overall_impact,
            "requires_downtime": plan.requires_downtime,
            "fully_reversible": plan.fully_reversible,
            "estimated_duration_seconds": plan.estimated_duration_seconds,
            "impact_summary": plan.impact_summary,
            "actions": [
                {
                    "id": str(a.id),
                    "order": a.order,
                    "action_type": a.action_type,
                    "title": a.title,
                    "description": a.description,
                    "target": a.target,
                    "impact_level": a.impact_level,
                    "impact_description": a.impact_description,
                    "reversible": a.reversible,
                    "optional": a.optional,
                }
                for a in plan.actions
            ],
            "warnings": _build_warnings(plan),
        }

        plan.status = PlanStatus.AWAITING_CONSENT
        await self.db.commit()
        return payload

    # ── 3a. APPROVE ───────────────────────────────────────────────────────────

    async def approve(
        self,
        plan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        actor: str,
        notes: str | None = None,
        excluded_action_ids: list[str] | None = None,
        actor_ip: str | None = None,
        actor_ua: str | None = None,
    ) -> RemediationExecution:
        """
        Record user consent and create an execution.
        Does NOT start execution — caller must call execute(execution_id).
        This separation lets the API return the execution ID immediately
        while execution runs in background.
        """
        plan = await self._load_plan(plan_id, tenant_id)
        if plan.status not in (PlanStatus.AWAITING_CONSENT, PlanStatus.DRAFT):
            raise ValueError(f"Plan cannot be approved in status: {plan.status}")

        consent = ConsentRecord(
            plan_id=plan.id,
            actor=actor,
            decision="approved",
            notes=notes,
            plan_snapshot=await self.get_consent_payload(plan_id, tenant_id),
            excluded_action_ids=excluded_action_ids or [],
            actor_ip=actor_ip,
            actor_ua=actor_ua,
        )
        self.db.add(consent)

        execution = RemediationExecution(
            plan_id=plan.id,
            tenant_id=tenant_id,
            status=ExecutionStatus.PENDING,
            actions_total=len([
                a for a in plan.actions
                if str(a.id) not in (excluded_action_ids or [])
            ]),
        )
        self.db.add(execution)

        plan.status = PlanStatus.APPROVED
        await self.db.commit()
        await self.db.refresh(execution)
        return execution

    # ── 3b. REJECT ────────────────────────────────────────────────────────────

    async def reject(
        self,
        plan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        actor: str,
        notes: str | None = None,
    ):
        plan = await self._load_plan(plan_id, tenant_id)
        consent = ConsentRecord(
            plan_id=plan.id,
            actor=actor,
            decision="rejected",
            notes=notes,
            plan_snapshot={},
            excluded_action_ids=[],
        )
        self.db.add(consent)
        plan.status = PlanStatus.REJECTED
        await self.db.commit()

    # ── 4. EXECUTE ────────────────────────────────────────────────────────────

    async def execute(self, execution_id: uuid.UUID, tenant_id: uuid.UUID):
        """
        Run the execution. Designed to run as a background task.
        Publishes real-time status updates to Redis pub/sub channel.
        """
        execution = await self._load_execution(execution_id)
        tenant = await self._require(Tenant, execution.tenant_id, execution.tenant_id)

        execution.status = ExecutionStatus.RUNNING
        execution.started_at = datetime.now(timezone.utc)
        execution.plan.status = PlanStatus.EXECUTING
        await self.db.commit()

        await self._publish(execution_id, {"event": "started", "execution_id": str(execution_id)})

        excluded = set(execution.plan.consent.excluded_action_ids if execution.plan.consent else [])
        actions = [a for a in execution.plan.actions if str(a.id) not in excluded]

        completed_orders: set[int] = set()
        failed = False

        for action in actions:
            # Respect dependency chain
            if action.depends_on_order is not None and action.depends_on_order not in completed_orders:
                result = ActionResult(
                    execution_id=execution_id,
                    action_id=action.id,
                    status="skipped",
                    output={"reason": f"dependency on order {action.depends_on_order} not met"},
                )
                self.db.add(result)
                execution.actions_failed += 1
                await self.db.commit()
                await self._publish(execution_id, {"event": "action_skipped", "action": action.title})
                failed = True
                continue

            result = await self._run_action(action, tenant, execution_id)

            if result.status == "success":
                completed_orders.add(action.order)
                execution.actions_completed += 1
            else:
                execution.actions_failed += 1
                failed = True
                # Non-optional failure stops the chain and triggers rollback
                if not action.optional:
                    await self.db.commit()
                    await self._publish(execution_id, {
                        "event": "action_failed",
                        "action": action.title,
                        "error": result.error,
                    })
                    await self._auto_rollback(execution, tenant)
                    return

            await self.db.commit()

        execution.completed_at = datetime.now(timezone.utc)
        execution.status = ExecutionStatus.FAILED if failed else ExecutionStatus.COMPLETED
        execution.plan.status = PlanStatus.FAILED if failed else PlanStatus.COMPLETED
        execution.summary = f"{execution.actions_completed}/{execution.actions_total} actions completed."
        await self.db.commit()

        await self._publish(execution_id, {
            "event": "completed",
            "status": execution.status,
            "summary": execution.summary,
        })

    # ── 5. ROLLBACK ───────────────────────────────────────────────────────────

    async def rollback(self, execution_id: uuid.UUID, actor: str):
        """
        Manually triggered rollback — undoes all reversible actions
        in reverse order.
        """
        execution = await self._load_execution(execution_id)
        tenant = await self._require(Tenant, execution.tenant_id, execution.tenant_id)
        await self._do_rollback(execution, tenant, triggered_by=actor)

    # ── INTERNAL ──────────────────────────────────────────────────────────────

    async def _run_action(
        self,
        action: RemediationAction,
        tenant: Tenant,
        execution_id: uuid.UUID,
    ) -> ActionResult:
        adapter = ADAPTER_REGISTRY.get(action.action_type)

        result = ActionResult(
            execution_id=execution_id,
            action_id=action.id,
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        self.db.add(result)
        await self.db.flush()

        await self._publish(execution_id, {"event": "action_started", "action": action.title, "target": action.target})

        if adapter is None:
            result.status = "skipped"
            result.output = {"reason": f"no adapter for {action.action_type}"}
            result.completed_at = datetime.now(timezone.utc)
            await self.db.flush()
            return result

        t0 = datetime.now(timezone.utc)
        adapter_result = await adapter.execute(action.params, tenant.integrations)
        duration_ms = int((datetime.now(timezone.utc) - t0).total_seconds() * 1000)

        result.status = "success" if adapter_result.success else "failed"
        result.output = adapter_result.output
        result.error = adapter_result.error
        result.duration_ms = duration_ms
        result.completed_at = datetime.now(timezone.utc)

        event = "action_success" if adapter_result.success else "action_failed"
        await self._publish(execution_id, {
            "event": event,
            "action": action.title,
            "target": action.target,
            "duration_ms": duration_ms,
            "error": adapter_result.error,
        })

        await self.db.flush()
        return result

    async def _auto_rollback(self, execution: RemediationExecution, tenant: Tenant):
        """Called automatically when a non-optional action fails."""
        execution.rollback_triggered = True
        await self.db.commit()
        await self._publish(execution.id, {"event": "rollback_started", "reason": "action_failed"})
        await self._do_rollback(execution, tenant, triggered_by="system")

    async def _do_rollback(self, execution: RemediationExecution, tenant: Tenant, triggered_by: str):
        execution.status = ExecutionStatus.ROLLING_BACK
        await self.db.commit()

        # Rollback in reverse order, only successful + reversible actions
        succeeded = [
            ar for ar in execution.action_results
            if ar.status == "success" and ar.action.reversible and not ar.rolled_back
        ]
        succeeded.sort(key=lambda r: r.action.order, reverse=True)

        for action_result in succeeded:
            action = action_result.action
            adapter = ADAPTER_REGISTRY.get(action.action_type)
            if not adapter:
                continue

            rb_result = await adapter.rollback(action.params, action_result.output, tenant.integrations)
            action_result.rolled_back = rb_result.success
            action_result.rollback_result = {"success": rb_result.success, "output": rb_result.output, "error": rb_result.error}

            await self._publish(execution.id, {
                "event": "rollback_action",
                "action": action.title,
                "success": rb_result.success,
            })

        execution.status = ExecutionStatus.ROLLED_BACK
        execution.plan.status = PlanStatus.ROLLED_BACK
        await self.db.commit()
        await self._publish(execution.id, {"event": "rollback_completed", "triggered_by": triggered_by})

    async def _publish(self, execution_id: uuid.UUID, data: dict):
        channel = _CHANNEL.format(execution_id=execution_id)
        await self.redis.publish(channel, json.dumps(data))

    async def _require(self, model, obj_id, tenant_id):
        result = await self.db.get(model, obj_id)
        if result is None:
            raise ValueError(f"{model.__name__} {obj_id} not found")
        return result

    async def _load_plan(self, plan_id: uuid.UUID, tenant_id: uuid.UUID) -> RemediationPlan:
        result = await self.db.execute(
            select(RemediationPlan)
            .where(RemediationPlan.id == plan_id, RemediationPlan.tenant_id == tenant_id)
            .options(selectinload(RemediationPlan.actions), selectinload(RemediationPlan.consent))
        )
        plan = result.scalar_one_or_none()
        if not plan:
            raise ValueError(f"Plan {plan_id} not found")
        return plan

    async def _load_execution(self, execution_id: uuid.UUID) -> RemediationExecution:
        result = await self.db.execute(
            select(RemediationExecution)
            .where(RemediationExecution.id == execution_id)
            .options(
                selectinload(RemediationExecution.plan).selectinload(RemediationPlan.actions),
                selectinload(RemediationExecution.plan).selectinload(RemediationPlan.consent),
                selectinload(RemediationExecution.action_results).selectinload(ActionResult.action),
            )
        )
        execution = result.scalar_one_or_none()
        if not execution:
            raise ValueError(f"Execution {execution_id} not found")
        return execution


# ── HELPERS ───────────────────────────────────────────────────────────────────

def _build_impact_summary(plan_data: dict, actions: list[RemediationAction]) -> dict:
    affected_users = set()
    affected_endpoints = set()
    irreversible = []
    warnings = []

    for a in actions:
        if a.params.get("upn") or a.params.get("user_id"):
            affected_users.add(a.params.get("upn") or a.params.get("user_id"))
        if a.params.get("endpoint_name") or a.params.get("mac"):
            affected_endpoints.add(a.params.get("endpoint_name") or a.params.get("mac"))
        if not a.reversible:
            irreversible.append(a.action_type)

    if irreversible:
        warnings.append(f"{len(irreversible)} action(s) cannot be undone automatically.")
    if plan_data.get("requires_downtime"):
        warnings.append("This remediation will cause temporary service interruption.")

    return {
        "affected_users": list(affected_users),
        "affected_endpoints": list(affected_endpoints),
        "irreversible_actions": irreversible,
        "warnings": warnings,
    }


def _build_warnings(plan: RemediationPlan) -> list[str]:
    warnings = []
    irreversible = [a for a in plan.actions if not a.reversible]
    if irreversible:
        names = ", ".join(a.title for a in irreversible)
        warnings.append(f"The following actions CANNOT be undone: {names}")
    if plan.requires_downtime:
        warnings.append("This plan requires temporary service downtime.")
    if plan.overall_impact in (ImpactLevel.HIGH, ImpactLevel.CRITICAL):
        warnings.append(f"Impact level is {plan.overall_impact.upper()}. Review carefully before approving.")
    return warnings
