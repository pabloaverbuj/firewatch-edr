"""
Network adapter — MikroTik RouterOS via API.
Handles endpoint isolation, IP blocking, VLAN quarantine.
"""
import librouteros
from librouteros import connect
from app.engine.adapters.base import BaseAdapter, AdapterResult


class NetworkIsolateAdapter(BaseAdapter):
    """Isolate an endpoint by blocking its MAC in the MikroTik bridge."""

    async def execute(self, params: dict, tenant_config: dict) -> AdapterResult:
        # params: {"mac": "AA:BB:CC:DD:EE:FF", "endpoint_name": "PC-CONTADURIA-01"}
        cfg = tenant_config.get("mikrotik", {})
        try:
            api = _connect(cfg)
            mac = params["mac"]
            # Add to address-list "quarantine"
            api("/ip/firewall/address-list/add", **{
                "list": "quarantine",
                "address": mac,
                "comment": f"Firewatch auto-isolate: {params.get('endpoint_name', mac)}",
            })
            # Drop all traffic from quarantine list
            api.close()
            return AdapterResult(success=True, output={"quarantine_entry": mac})
        except Exception as e:
            return AdapterResult(success=False, error=str(e))

    async def rollback(self, params: dict, execution_output: dict, tenant_config: dict) -> AdapterResult:
        cfg = tenant_config.get("mikrotik", {})
        try:
            api = _connect(cfg)
            mac = execution_output.get("quarantine_entry", params["mac"])
            entries = list(api("/ip/firewall/address-list/print", **{"?list": "quarantine", "?address": mac}))
            for entry in entries:
                api("/ip/firewall/address-list/remove", **{"=numbers": entry[".id"]})
            api.close()
            return AdapterResult(success=True, output={"removed": mac})
        except Exception as e:
            return AdapterResult(success=False, error=str(e))

    def is_reversible(self, params: dict) -> bool:
        return True


class BlockIPAdapter(BaseAdapter):
    """Block an IP in the MikroTik firewall (C2, malicious external IP)."""

    async def execute(self, params: dict, tenant_config: dict) -> AdapterResult:
        # params: {"ip": "185.220.101.47", "reason": "C2 Emotet"}
        cfg = tenant_config.get("mikrotik", {})
        try:
            api = _connect(cfg)
            ip = params["ip"]
            api("/ip/firewall/address-list/add", **{
                "list": "blacklist",
                "address": ip,
                "comment": f"Firewatch block: {params.get('reason', 'malicious')}",
            })
            api.close()
            return AdapterResult(success=True, output={"blocked_ip": ip})
        except Exception as e:
            return AdapterResult(success=False, error=str(e))

    async def rollback(self, params: dict, execution_output: dict, tenant_config: dict) -> AdapterResult:
        cfg = tenant_config.get("mikrotik", {})
        try:
            api = _connect(cfg)
            ip = params["ip"]
            entries = list(api("/ip/firewall/address-list/print", **{"?list": "blacklist", "?address": ip}))
            for entry in entries:
                api("/ip/firewall/address-list/remove", **{"=numbers": entry[".id"]})
            api.close()
            return AdapterResult(success=True, output={"unblocked_ip": ip})
        except Exception as e:
            return AdapterResult(success=False, error=str(e))

    def is_reversible(self, params: dict) -> bool:
        return True


def _connect(cfg: dict):
    return connect(
        username=cfg.get("user", "admin"),
        password=cfg.get("password", ""),
        host=cfg.get("host", "192.168.88.1"),
        port=int(cfg.get("port", 8728)),
    )
