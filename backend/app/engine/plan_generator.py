"""
Uses Claude to analyze an incident and generate a structured remediation plan.
Falls back to a realistic demo plan when no API key is configured.
"""
import json
from anthropic import AsyncAnthropic
from app.config import settings
from app.models.incident import Incident
from app.models.remediation import ActionType, ImpactLevel


def _get_client():
    if settings.anthropic_api_key:
        return AsyncAnthropic(api_key=settings.anthropic_api_key)
    return None


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
      "params": { },
      "impact_level": "informational|low|medium|high|critical",
      "impact_description": "what the user will experience",
      "reversible": true|false,
      "rollback_params": { },
      "optional": true|false,
      "depends_on_order": null
    }
  ]
}

Available action types:
- network_isolate, block_ip, identity_block_user,
  identity_revoke_sessions, identity_force_password_reset, notify_teams

Rules:
- Containment actions first, notifications last
- Mark notifications as optional:true
- Mark irreversible actions with reversible:false
- If severity is critical, always include network_isolate and identity_block_user
"""

DEMO_PLAN = {
    "title": "Ransomware Precursor — Contención de PC-CONTADURIA-01",
    "description": (
        "winword.exe lanzó powershell.exe con payload Base64 que contactó una IP C2 de Emotet. "
        "Este plan contiene el endpoint, bloquea al usuario y corta la comunicación C2."
    ),
    "ai_analysis": (
        "[MODO DEMO — sin API key] "
        "winword.exe → powershell.exe con argumento -EncodedCommand indica ejecución de macro maliciosa. "
        "La resolución de 185.220.101.47 (categorizada como C2 activo de Emotet/Ryuk) sugiere que el dropper "
        "ya estableció canal de comando. Técnicas MITRE: T1059.001 (PowerShell), T1071.001 (C2 over HTTP), "
        "T1027 (Obfuscated Files). Confianza: 94%. Sin contención inmediata, probabilidad de movimiento "
        "lateral y cifrado de archivos en los próximos 15-30 minutos."
    ),
    "ai_confidence": 0.94,
    "overall_impact": "critical",
    "requires_downtime": True,
    "fully_reversible": False,
    "estimated_duration_seconds": 12,
    "actions": [
        {
            "order": 0,
            "action_type": ActionType.NETWORK_ISOLATE,
            "title": "Aislar PC-CONTADURIA-01 de la red",
            "description": "Bloquea el MAC del endpoint en el bridge de MikroTik para cortar toda conectividad.",
            "target": "PC-CONTADURIA-01",
            "params": {"mac": "AA:BB:CC:11:22:33", "endpoint_name": "PC-CONTADURIA-01"},
            "impact_level": "critical",
            "impact_description": "El equipo pierde acceso a la red inmediatamente. maria.gomez no podrá trabajar hasta que se restaure.",
            "reversible": True,
            "rollback_params": {"mac": "AA:BB:CC:11:22:33", "endpoint_name": "PC-CONTADURIA-01"},
            "optional": False,
            "depends_on_order": None,
        },
        {
            "order": 1,
            "action_type": ActionType.BLOCK_IP,
            "title": "Bloquear IP C2 185.220.101.47",
            "description": "Agrega la IP del servidor C2 de Emotet a la lista negra del firewall MikroTik.",
            "target": "185.220.101.47",
            "params": {"ip": "185.220.101.47", "reason": "Emotet C2 — detectado por Firewatch AI"},
            "impact_level": "medium",
            "impact_description": "La IP queda bloqueada para todos los clientes de la red, no solo para este endpoint.",
            "reversible": True,
            "rollback_params": {"ip": "185.220.101.47"},
            "optional": False,
            "depends_on_order": None,
        },
        {
            "order": 2,
            "action_type": ActionType.IDENTITY_BLOCK_USER,
            "title": "Deshabilitar usuario maria.gomez en Entra ID",
            "description": "Deshabilita la cuenta para prevenir que el atacante la use para movimiento lateral.",
            "target": "maria.gomez@empresa.com",
            "params": {"upn": "maria.gomez@empresa.com"},
            "impact_level": "high",
            "impact_description": "maria.gomez no podrá acceder a ningún servicio Microsoft (M365, Teams, SharePoint).",
            "reversible": True,
            "rollback_params": {"upn": "maria.gomez@empresa.com"},
            "optional": False,
            "depends_on_order": None,
        },
        {
            "order": 3,
            "action_type": ActionType.IDENTITY_REVOKE_SESSIONS,
            "title": "Revocar todas las sesiones activas de maria.gomez",
            "description": "Cierra todos los tokens de acceso activos. Impide uso de sesiones ya comprometidas.",
            "target": "maria.gomez@empresa.com",
            "params": {"upn": "maria.gomez@empresa.com"},
            "impact_level": "high",
            "impact_description": "Todas las sesiones activas se cierran inmediatamente. No se puede revertir automáticamente.",
            "reversible": False,
            "rollback_params": {},
            "optional": False,
            "depends_on_order": 2,
        },
        {
            "order": 4,
            "action_type": ActionType.NOTIFY_TEAMS,
            "title": "Notificar al equipo de IT via Teams",
            "description": "Envía alerta al canal de seguridad con el resumen del incidente.",
            "target": "Canal IT Security",
            "params": {
                "title": "🚨 Incidente crítico — PC-CONTADURIA-01",
                "body": "Ransomware precursor detectado. Contención ejecutada por Firewatch AI.",
                "severity": "critical",
                "facts": [
                    {"name": "Endpoint", "value": "PC-CONTADURIA-01"},
                    {"name": "Usuario", "value": "maria.gomez"},
                    {"name": "IP C2", "value": "185.220.101.47"},
                    {"name": "Confianza AI", "value": "94%"},
                ],
            },
            "impact_level": "informational",
            "impact_description": "Solo envía una notificación, no afecta ningún servicio.",
            "reversible": False,
            "rollback_params": {},
            "optional": True,
            "depends_on_order": None,
        },
    ],
}


async def generate_plan(incident: Incident) -> dict:
    client = _get_client()

    if client is None:
        # No API key — return realistic demo plan
        return DEMO_PLAN

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
