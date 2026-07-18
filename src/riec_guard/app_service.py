
from __future__ import annotations

from dataclasses import dataclass

from .errors import FeatureNotImplementedError
from .settings import SeedSettings


@dataclass(slots=True)
class AuditService:
    """Single shared service boundary for CLI, tests, and UI.

    TASK-034 replaces the seed method with the deterministic end-to-end service.
    """

    settings: SeedSettings = SeedSettings()

    def seed_status(self) -> dict[str, str]:
        self.settings.assert_safe()
        return {"status": "seed", "next_task": "TASK-001"}

    def run_audit(self, *args: object, **kwargs: object) -> object:
        raise FeatureNotImplementedError(
            "The deterministic audit pipeline is implemented by TASK-014 through TASK-034."
        )
