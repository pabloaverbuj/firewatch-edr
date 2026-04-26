from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AdapterResult:
    success: bool
    output: dict = field(default_factory=dict)
    error: str | None = None


class BaseAdapter(ABC):
    """
    Each adapter handles one category of action (network, identity, etc.).
    It must implement execute() and rollback().
    """

    @abstractmethod
    async def execute(self, params: dict, tenant_config: dict) -> AdapterResult:
        """Execute the action. Must be idempotent where possible."""
        ...

    @abstractmethod
    async def rollback(self, params: dict, execution_output: dict, tenant_config: dict) -> AdapterResult:
        """Undo what execute() did, using the original params + what execute() returned."""
        ...

    @abstractmethod
    def is_reversible(self, params: dict) -> bool:
        """Return False if this specific invocation cannot be undone."""
        ...
