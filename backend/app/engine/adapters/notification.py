"""
Notification adapter — Teams webhook + email via M365.
Always informational, never has rollback.
"""
import httpx
from app.engine.adapters.base import BaseAdapter, AdapterResult


class TeamsNotifyAdapter(BaseAdapter):
    """Send adaptive card to a Teams channel via incoming webhook."""

    async def execute(self, params: dict, tenant_config: dict) -> AdapterResult:
        # params: {"title": "...", "body": "...", "severity": "critical"}
        webhook_url = tenant_config.get("teams_webhook")
        if not webhook_url:
            return AdapterResult(success=True, output={"skipped": "no_webhook_configured"})

        color_map = {"critical": "FF0000", "high": "FF8C00", "medium": "FFC300", "low": "00B0F0"}
        color = color_map.get(params.get("severity", "medium"), "FFC300")

        card = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": color,
            "summary": params.get("title", "Firewatch Alert"),
            "sections": [{
                "activityTitle": f"🔥 {params.get('title', 'Firewatch Alert')}",
                "activityText": params.get("body", ""),
                "facts": params.get("facts", []),
            }],
        }

        try:
            async with httpx.AsyncClient() as client:
                r = await client.post(webhook_url, json=card, timeout=10)
                r.raise_for_status()
            return AdapterResult(success=True, output={"notified": "teams"})
        except Exception as e:
            return AdapterResult(success=False, error=str(e))

    async def rollback(self, params: dict, execution_output: dict, tenant_config: dict) -> AdapterResult:
        # Notifications are not reversible — but that's fine, no rollback needed
        return AdapterResult(success=True, output={"rollback": "not_applicable"})

    def is_reversible(self, params: dict) -> bool:
        return False
