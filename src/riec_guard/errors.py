
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class ErrorEnvelope:
    """Minimal seed error type; TASK-008/009 replace this with canonical models."""

    code: str
    message: str
    details: dict[str, Any] | None = None


class FeatureNotImplementedError(RuntimeError):
    """Raised when a seed-only method is called before its scheduled task."""
