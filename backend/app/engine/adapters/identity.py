"""
Identity adapter — Microsoft Entra ID (Azure AD) via Microsoft Graph API.
Handles user blocking, session revocation, MFA reset, password reset.
"""
import httpx
from app.engine.adapters.base import BaseAdapter, AdapterResult

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class BlockUserAdapter(BaseAdapter):
    """Disable a user account in Entra ID."""

    async def execute(self, params: dict, tenant_config: dict) -> AdapterResult:
        # params: {"user_id": "...", "upn": "maria.gomez@company.com"}
        cfg = tenant_config.get("entra_id", {})
        if not cfg.get("tenant_id"):
            return AdapterResult(success=True, output={"demo": True, "simulated": "identity_block_user", "user": params.get("upn")})
        token = await _get_token(tenant_config)
        user_id = params.get("user_id") or params.get("upn")
        try:
            async with httpx.AsyncClient() as client:
                r = await client.patch(
                    f"{GRAPH_BASE}/users/{user_id}",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"accountEnabled": False},
                )
                r.raise_for_status()
            return AdapterResult(success=True, output={"blocked_user": user_id})
        except Exception as e:
            return AdapterResult(success=False, error=str(e))

    async def rollback(self, params: dict, execution_output: dict, tenant_config: dict) -> AdapterResult:
        token = await _get_token(tenant_config)
        user_id = execution_output.get("blocked_user")
        try:
            async with httpx.AsyncClient() as client:
                r = await client.patch(
                    f"{GRAPH_BASE}/users/{user_id}",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"accountEnabled": True},
                )
                r.raise_for_status()
            return AdapterResult(success=True, output={"unblocked_user": user_id})
        except Exception as e:
            return AdapterResult(success=False, error=str(e))

    def is_reversible(self, params: dict) -> bool:
        return True


class RevokeSessionsAdapter(BaseAdapter):
    """Revoke all active refresh tokens for a user. Cannot be undone."""

    async def execute(self, params: dict, tenant_config: dict) -> AdapterResult:
        # params: {"user_id": "...", "upn": "..."}
        cfg = tenant_config.get("entra_id", {})
        if not cfg.get("tenant_id"):
            return AdapterResult(success=True, output={"demo": True, "simulated": "identity_revoke_sessions", "user": params.get("upn")})
        token = await _get_token(tenant_config)
        user_id = params.get("user_id") or params.get("upn")
        try:
            async with httpx.AsyncClient() as client:
                r = await client.post(
                    f"{GRAPH_BASE}/users/{user_id}/revokeSignInSessions",
                    headers={"Authorization": f"Bearer {token}"},
                )
                r.raise_for_status()
            return AdapterResult(success=True, output={"revoked_sessions_for": user_id})
        except Exception as e:
            return AdapterResult(success=False, error=str(e))

    async def rollback(self, params: dict, execution_output: dict, tenant_config: dict) -> AdapterResult:
        # Sessions cannot be restored — user must re-authenticate
        return AdapterResult(
            success=False,
            error="Session revocation is irreversible. User must re-authenticate.",
        )

    def is_reversible(self, params: dict) -> bool:
        return False


class ForcePasswordResetAdapter(BaseAdapter):
    """Force the user to change password at next sign-in."""

    async def execute(self, params: dict, tenant_config: dict) -> AdapterResult:
        token = await _get_token(tenant_config)
        user_id = params.get("user_id") or params.get("upn")
        try:
            async with httpx.AsyncClient() as client:
                r = await client.patch(
                    f"{GRAPH_BASE}/users/{user_id}",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"passwordProfile": {"forceChangePasswordNextSignIn": True}},
                )
                r.raise_for_status()
            return AdapterResult(success=True, output={"password_reset_forced": user_id})
        except Exception as e:
            return AdapterResult(success=False, error=str(e))

    async def rollback(self, params: dict, execution_output: dict, tenant_config: dict) -> AdapterResult:
        return AdapterResult(success=False, error="Password reset flag cannot be reversed automatically.")

    def is_reversible(self, params: dict) -> bool:
        return False


async def _get_token(tenant_config: dict) -> str:
    cfg = tenant_config.get("entra_id", {})
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"https://login.microsoftonline.com/{cfg['tenant_id']}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": cfg["client_id"],
                "client_secret": cfg["client_secret"],
                "scope": "https://graph.microsoft.com/.default",
            },
        )
        r.raise_for_status()
        return r.json()["access_token"]
