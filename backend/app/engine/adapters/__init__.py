from app.models.remediation import ActionType
from app.engine.adapters.network import NetworkIsolateAdapter, BlockIPAdapter
from app.engine.adapters.identity import BlockUserAdapter, RevokeSessionsAdapter, ForcePasswordResetAdapter
from app.engine.adapters.notification import TeamsNotifyAdapter

# Registry: action_type → adapter instance
ADAPTER_REGISTRY: dict = {
    ActionType.NETWORK_ISOLATE:              NetworkIsolateAdapter(),
    ActionType.NETWORK_RESTORE:              NetworkIsolateAdapter(),  # rollback of isolate
    ActionType.BLOCK_IP:                     BlockIPAdapter(),
    ActionType.UNBLOCK_IP:                   BlockIPAdapter(),
    ActionType.IDENTITY_BLOCK_USER:          BlockUserAdapter(),
    ActionType.IDENTITY_UNBLOCK_USER:        BlockUserAdapter(),
    ActionType.IDENTITY_REVOKE_SESSIONS:     RevokeSessionsAdapter(),
    ActionType.IDENTITY_FORCE_PASSWORD_RESET: ForcePasswordResetAdapter(),
    ActionType.NOTIFY_TEAMS:                 TeamsNotifyAdapter(),
}
