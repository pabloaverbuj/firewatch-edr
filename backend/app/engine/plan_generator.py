"""
Uses Claude to analyze an incident and generate a structured remediation plan.
"""
import json
from anthropic import AsyncAnthropic
from app.config import settings
from app.models.incident import Incident
from app.models.remediation import ActionType, ImpactLevel

client = AsyncAnthropic(api_key=settings.anthropic_api_key)

SYSTEM_PROMPT = """You are Firewatch's AI SOC Analyst. Your job is to analyze security incidents
and generate precise, actionable remediation plans.

You output ONLY valid JSON — no explanations outside the JSON structure.

For each incident you receive, return a JSON object with this exact schema:
{
  "title": "short plan title (max 80 chars)",
  "description": "1-2 sentence summary of what happened and why this plan addresses it",
  "ai_analysis": "detailed technical analysis of the threat, attacker TTPs, and risk",
  "ai_confidence": 0.0-1.0,
  "overall_impact": "informational|low|medium|high|critical",
  "requires_downtime": true|false,
  "fully_reversible": true|false,
  "estimated_duration_seconds": number,
  "actions": [
    {
      "order": 0,
      "action_type": "one of the action types below",
      "title": "short action title",
      "description": "what this action does and why",
      "target": "hostname, username, IP, or process name",
      "params": { ... adapter-specific parameters ... },
      "impact_level": "informational|low|medium|high|critical",
      "impact_description": "what the user will experience",
      "reversible": true|false,
      "rollback_params": { ... params needed to undo this ... },
      "optional": true|false,
      "depends_on_order": null or order number of required preceding action
    }
  ]
}

Available action types:
- network_isolate: Block endpoint MAC in MikroTik. params: {mac, endpoint_name}
- network_restore: Unblock endpoint. params: {mac, endpoint_name}
- block_ip: Block IP in MikroTik firewall. params: {ip, reason}
- identity_block_user: Disable user in Entra ID. params: {user_id or upn}
- identity_revoke_sessions: Revoke all user sessions. params: {user_id or upn}
- identity_force_password_reset: Force password change. params: {user_id or upn}
- notify_teams: Send Teams alert. params: {title, body, severity, facts:[{name,value}]}

Rules:
- Order actions from most critical to least (containment first, notifications last)
- Mark notifications as optional:true
- Mark destructive/irreversible actions explicitly with reversible:false
- Be specific about impact_description — the user must understand exactly what will happen
- If severity is critical, always include network_isolate and identity_block_user
- Always end with a notify_teams action
"""


async def generate_plan(incident: Incident) -> dict:
    """
    Call Claude with incident data, return structured plan dict.
    Raises ValueError if Claude returns invalid JSON.
    """
    incident_context = {
        "title": incident.title,
        "severity": incident.severity,
        "affected_endpoint": incident.affected_endpoint,
        "affected_user": incident.affected_user,
        "affected_ip": incident.affected_ip,
        "raw_data": incident.raw_data,
    }

    message = await client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"Generate a remediation plan for this incident:\n\n{json.dumps(incident_context, indent=2)}",
        }],
    )

    raw = message.content[0].text.strip()

    # Strip markdown code block if Claude wraps it
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]

    try:
        plan_data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Claude returned invalid JSON: {e}\nRaw response: {raw[:500]}")

    _validate_plan_data(plan_data)
    return plan_data


def _validate_plan_data(data: dict):
    required = {"title", "actions", "overall_impact", "ai_confidence"}
    missing = required - set(data.keys())
    if missing:
        raise ValueError(f"Plan data missing required fields: {missing}")

    valid_types = {v for k, v in vars(ActionType).items() if not k.startswith("_")}
    for action in data.get("actions", []):
        if action.get("action_type") not in valid_types:
            raise ValueError(f"Unknown action_type: {action.get('action_type')}")

    valid_impacts = {v for k, v in vars(ImpactLevel).items() if not k.startswith("_")}
    if data.get("overall_impact") not in valid_impacts:
        raise ValueError(f"Invalid overall_impact: {data.get('overall_impact')}")
