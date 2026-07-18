
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class SeedSettings:
    """Safe seed defaults. TASK-003 implements the full settings contract."""

    hosted_mode: bool = True
    public_mode: bool = True
    ephemeral_root: Path = Path("runs")

    def assert_safe(self) -> None:
        if not self.public_mode:
            raise RuntimeError("The public repository seed cannot enable private mode.")
