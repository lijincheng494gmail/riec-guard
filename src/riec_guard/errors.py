
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


@dataclass(slots=True)
class ErrorEnvelope:
    """Minimal seed error type; TASK-008/009 replace this with canonical models."""

    code: str
    message: str
    details: dict[str, Any] | None = None


class ErrorCode(StrEnum):
    """Stable public error codes for guarded sources and ephemeral runs."""

    UNSUPPORTED_FILE_TYPE = "unsupported_file_type"
    ARCHIVE_UPLOAD_REJECTED = "archive_upload_rejected"
    UPLOAD_TOO_LARGE = "upload_too_large"
    TOO_MANY_ROWS = "too_many_rows"
    TOO_MANY_COLUMNS = "too_many_columns"
    MALFORMED_CSV = "malformed_csv"
    UNSAFE_DISPLAY_FILENAME = "unsafe_display_filename"
    BINARY_OR_NUL_CONTENT = "binary_or_nul_content"
    SOURCE_NOT_FOUND = "source_not_found"
    RUN_NOT_FOUND = "run_not_found"
    STORAGE_FAILURE = "storage_failure"
    CLEANUP_FAILURE = "cleanup_failure"


class ApplicationError(RuntimeError):
    """Typed application failure whose public representation contains safe metadata only."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        field: str | None = None,
        source_id: str | None = None,
        run_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.field = field
        self.source_id = source_id
        self.run_id = run_id

    def to_envelope(self) -> ErrorEnvelope:
        details = {
            key: value
            for key, value in (
                ("field", self.field),
                ("source_id", self.source_id),
                ("run_id", self.run_id),
            )
            if value is not None
        }
        return ErrorEnvelope(
            code=self.code.value,
            message=self.message,
            details=details or None,
        )


class FeatureNotImplementedError(RuntimeError):
    """Raised when a seed-only method is called before its scheduled task."""
