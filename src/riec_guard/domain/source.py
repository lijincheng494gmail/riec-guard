from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from pathlib import Path

from riec_guard.settings import RunRoots

_SOURCE_ID_PATTERN = re.compile(r"\ASRC-[a-f0-9]{32}\Z")
_SAFE_SUFFIX_PATTERN = re.compile(r"\A\.[A-Za-z0-9]{1,16}\Z")


class SourceValidationError(ValueError):
    """Raised for source metadata errors without exposing local paths."""


def _new_source_id() -> str:
    return f"SRC-{uuid.uuid4().hex}"


def _normalize_suffix(suffix: str) -> str:
    if not suffix.startswith("."):
        suffix = f".{suffix}"
    if not _SAFE_SUFFIX_PATTERN.fullmatch(suffix):
        raise SourceValidationError("source suffix must be a simple file extension")
    return suffix.lower()


@dataclass(frozen=True, slots=True)
class UploadedSource:
    """Public upload descriptor whose original name is display metadata only."""

    source_id: str
    original_display_name: str
    media_type: str | None = None

    @classmethod
    def from_upload(
        cls,
        original_display_name: str,
        *,
        media_type: str | None = None,
    ) -> "UploadedSource":
        return cls(
            source_id=_new_source_id(),
            original_display_name=original_display_name,
            media_type=media_type,
        )

    def __post_init__(self) -> None:
        if not _SOURCE_ID_PATTERN.fullmatch(self.source_id):
            raise SourceValidationError("source_id must be internally generated")

    def storage_filename(self, suffix: str = ".bin") -> str:
        return f"{self.source_id}{_normalize_suffix(suffix)}"

    def input_storage_path(self, run_roots: RunRoots, suffix: str = ".bin") -> Path:
        return run_roots.inputs / self.storage_filename(suffix)
