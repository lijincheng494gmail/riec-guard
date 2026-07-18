from __future__ import annotations

import hashlib
import os
import re
import shutil
import uuid
from collections.abc import Collection
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO

from riec_guard.domain.normalize import UploadLimits, normalize_csv_upload
from riec_guard.errors import ApplicationError, ErrorCode
from riec_guard.settings import RunRoots, RuntimeSettings

_SOURCE_ID_PATTERN = re.compile(r"\ASRC-[a-f0-9]{32}\Z")
_RUN_ID_PATTERN = re.compile(r"\ARUN-[a-f0-9]{32}\Z")
_BUILT_IN_KEY_PATTERN = re.compile(r"\A[a-z0-9][a-z0-9_-]{0,63}\Z")
_SAFE_SUFFIX_PATTERN = re.compile(r"\A\.[A-Za-z0-9]{1,16}\Z")
_RUN_SUBDIRECTORIES = ("inputs", "normalized", "artifacts", "telemetry")


class SourceKind(StrEnum):
    BUILT_IN = "built_in"
    UPLOADED_CSV = "uploaded_csv"


class SourceValidationError(ApplicationError):
    """Compatibility error for source metadata with a stable public code."""

    def __init__(self, message: str) -> None:
        super().__init__(ErrorCode.UNSAFE_DISPLAY_FILENAME, message, field="source")


def _new_source_id() -> str:
    return f"SRC-{uuid.uuid4().hex}"


def _normalize_suffix(suffix: str) -> str:
    if not suffix.startswith("."):
        suffix = f".{suffix}"
    if not _SAFE_SUFFIX_PATTERN.fullmatch(suffix):
        raise SourceValidationError("The source suffix must be a simple file extension.")
    return suffix.lower()


@dataclass(frozen=True, slots=True)
class SourceSpec:
    """Unified typed descriptor for run-owned built-in and uploaded public sources."""

    source_id: str
    original_display_name: str
    media_type: str | None = None
    kind: SourceKind = SourceKind.UPLOADED_CSV
    run_id: str | None = None
    built_in_key: str | None = None
    size_bytes: int | None = None
    data_row_count: int | None = None
    column_count: int | None = None
    raw_sha256: str | None = None
    normalized_sha256: str | None = None

    @classmethod
    def from_upload(
        cls,
        original_display_name: str,
        *,
        media_type: str | None = None,
    ) -> "SourceSpec":
        """Create metadata only; repository registration performs untrusted-name validation."""

        return cls(
            source_id=_new_source_id(),
            original_display_name=original_display_name,
            media_type=media_type,
        )

    @classmethod
    def from_built_in(
        cls,
        *,
        run_id: str,
        built_in_key: str,
        display_name: str,
    ) -> "SourceSpec":
        if not _BUILT_IN_KEY_PATTERN.fullmatch(built_in_key):
            raise SourceValidationError("The built-in source key is invalid.")
        return cls(
            source_id=_new_source_id(),
            original_display_name=display_name,
            media_type="text/csv",
            kind=SourceKind.BUILT_IN,
            run_id=run_id,
            built_in_key=built_in_key,
        )

    def __post_init__(self) -> None:
        if not _SOURCE_ID_PATTERN.fullmatch(self.source_id):
            raise SourceValidationError("The source ID must be internally generated.")
        if self.run_id is not None and not _RUN_ID_PATTERN.fullmatch(self.run_id):
            raise SourceValidationError("The run ID must be internally generated.")
        if self.kind is SourceKind.BUILT_IN and self.built_in_key is None:
            raise SourceValidationError("A built-in source requires a built-in key.")
        if self.kind is SourceKind.UPLOADED_CSV and self.built_in_key is not None:
            raise SourceValidationError("An uploaded source cannot have a built-in key.")

    @property
    def display_name(self) -> str:
        return self.original_display_name

    def storage_filename(self, suffix: str = ".bin") -> str:
        return f"{self.source_id}{_normalize_suffix(suffix)}"

    def input_storage_path(self, run_roots: RunRoots, suffix: str = ".bin") -> Path:
        return run_roots.inputs / self.storage_filename(suffix)

    def normalized_storage_path(self, run_roots: RunRoots, suffix: str = ".csv") -> Path:
        return run_roots.normalized / self.storage_filename(suffix)

    def to_metadata(self) -> dict[str, str | int | None]:
        return {
            "source_id": self.source_id,
            "kind": self.kind.value,
            "display_name": self.display_name,
            "media_type": self.media_type,
            "run_id": self.run_id,
            "built_in_key": self.built_in_key,
            "size_bytes": self.size_bytes,
            "data_row_count": self.data_row_count,
            "column_count": self.column_count,
            "raw_sha256": self.raw_sha256,
            "normalized_sha256": self.normalized_sha256,
        }


UploadedSource = SourceSpec


class SourceRepository:
    """Run-scoped source registry and explicit ephemeral cleanup boundary."""

    def __init__(
        self,
        settings: RuntimeSettings,
        *,
        limits: UploadLimits | None = None,
    ) -> None:
        settings.assert_safe()
        self._settings = settings
        self._ephemeral_root = settings.ephemeral_root
        self.limits = limits or UploadLimits()
        self._sources: dict[tuple[str, str], SourceSpec] = {}

    def create_run(self) -> RunRoots:
        roots = self._settings.create_run_roots()
        self._require_run(roots.run_id)
        return roots

    def register_built_in(
        self,
        run_id: str,
        *,
        built_in_key: str,
        display_name: str,
    ) -> SourceSpec:
        self._require_run(run_id)
        source = SourceSpec.from_built_in(
            run_id=run_id,
            built_in_key=built_in_key,
            display_name=display_name,
        )
        self._sources[(run_id, source.source_id)] = source
        return source

    def register_upload(
        self,
        run_id: str,
        *,
        display_name: str,
        media_type: str | None,
        payload: bytes | bytearray | memoryview | BinaryIO,
    ) -> SourceSpec:
        roots = self._require_run(run_id)
        normalized = normalize_csv_upload(
            payload,
            display_name=display_name,
            media_type=media_type,
            limits=self.limits,
        )
        source = replace(
            SourceSpec.from_upload(
                normalized.display_name,
                media_type=normalized.media_type,
            ),
            run_id=run_id,
            size_bytes=len(normalized.raw_bytes),
            data_row_count=normalized.data_row_count,
            column_count=normalized.column_count,
            raw_sha256=hashlib.sha256(normalized.raw_bytes).hexdigest(),
            normalized_sha256=hashlib.sha256(normalized.normalized_bytes).hexdigest(),
        )
        input_name = source.storage_filename(".csv")
        normalized_name = source.storage_filename(".csv")
        input_path = roots.inputs / input_name
        normalized_path = roots.normalized / normalized_name
        try:
            _write_new_file(roots.inputs, input_name, normalized.raw_bytes)
            _write_new_file(roots.normalized, normalized_name, normalized.normalized_bytes)
        except OSError:
            input_path.unlink(missing_ok=True)
            normalized_path.unlink(missing_ok=True)
            raise ApplicationError(
                ErrorCode.STORAGE_FAILURE,
                "The upload could not be stored safely.",
                run_id=run_id,
            ) from None
        self._sources[(run_id, source.source_id)] = source
        return source

    def get_source(self, run_id: str, source_id: str) -> SourceSpec:
        self._require_run(run_id)
        source = self._sources.get((run_id, source_id))
        if source is None:
            safe_source_id = source_id if _SOURCE_ID_PATTERN.fullmatch(source_id) else None
            raise ApplicationError(
                ErrorCode.SOURCE_NOT_FOUND,
                "The requested source was not found for this run.",
                source_id=safe_source_id,
                run_id=run_id,
            )
        return source

    def input_path(self, run_id: str, source_id: str) -> Path:
        roots = self._require_run(run_id)
        source = self.get_source(run_id, source_id)
        if source.kind is not SourceKind.UPLOADED_CSV:
            raise ApplicationError(
                ErrorCode.SOURCE_NOT_FOUND,
                "The requested source has no uploaded input file.",
                source_id=source.source_id,
                run_id=run_id,
            )
        return source.input_storage_path(roots, ".csv")

    def normalized_path(self, run_id: str, source_id: str) -> Path:
        roots = self._require_run(run_id)
        source = self.get_source(run_id, source_id)
        if source.kind is not SourceKind.UPLOADED_CSV:
            raise ApplicationError(
                ErrorCode.SOURCE_NOT_FOUND,
                "The requested source has no normalized file.",
                source_id=source.source_id,
                run_id=run_id,
            )
        return source.normalized_storage_path(roots, ".csv")

    def delete_run(self, run_id: str) -> bool:
        """Delete one validated child without following a run-root symlink."""

        if not _RUN_ID_PATTERN.fullmatch(run_id):
            raise _run_not_found()
        root = self._validated_ephemeral_root(require_exists=False)
        if root is None:
            self._remove_run_sources(run_id)
            return False
        candidate = root / run_id
        if candidate == root:
            raise _cleanup_failure(run_id)
        try:
            candidate.lstat()
        except FileNotFoundError:
            self._remove_run_sources(run_id)
            return False
        except OSError:
            raise _cleanup_failure(run_id) from None

        try:
            if candidate.is_symlink():
                candidate.unlink()
            else:
                resolved_candidate = candidate.resolve(strict=True)
                if resolved_candidate.parent != root or not resolved_candidate.is_dir():
                    raise _cleanup_failure(run_id)
                if not shutil.rmtree.avoids_symlink_attacks:
                    raise _cleanup_failure(run_id)
                shutil.rmtree(candidate)
        except ApplicationError:
            raise
        except OSError:
            raise _cleanup_failure(run_id) from None
        self._remove_run_sources(run_id)
        return True

    def cleanup_expired(
        self,
        *,
        older_than: datetime,
        active_run_ids: Collection[str] = (),
    ) -> tuple[str, ...]:
        """Delete expired run children while retaining explicitly active run IDs."""

        if older_than.tzinfo is None:
            raise ValueError("older_than must be timezone-aware")
        root = self._validated_ephemeral_root(require_exists=False)
        if root is None:
            return ()
        active = {run_id for run_id in active_run_ids if _RUN_ID_PATTERN.fullmatch(run_id)}
        removed: list[str] = []
        try:
            children = sorted(root.iterdir(), key=lambda child: child.name)
        except OSError:
            raise _cleanup_failure() from None
        for child in children:
            run_id = child.name
            if not _RUN_ID_PATTERN.fullmatch(run_id) or run_id in active:
                continue
            try:
                modified_at = datetime.fromtimestamp(child.lstat().st_mtime, tz=timezone.utc)
            except OSError:
                raise _cleanup_failure(run_id) from None
            if modified_at < older_than.astimezone(timezone.utc) and self.delete_run(run_id):
                removed.append(run_id)
        return tuple(removed)

    def _require_run(self, run_id: str) -> RunRoots:
        if not _RUN_ID_PATTERN.fullmatch(run_id):
            raise _run_not_found()
        root = self._validated_ephemeral_root(require_exists=True)
        if root is None:
            raise _run_not_found(run_id)
        run_root = root / run_id
        if run_root.is_symlink():
            raise _run_not_found(run_id)
        try:
            if run_root.resolve(strict=True).parent != root or not run_root.is_dir():
                raise _run_not_found(run_id)
        except (OSError, RuntimeError):
            raise _run_not_found(run_id) from None

        roots = RunRoots.under(root, run_id)
        for directory_name in _RUN_SUBDIRECTORIES:
            directory = run_root / directory_name
            try:
                if directory.is_symlink() or not directory.is_dir():
                    raise _run_not_found(run_id)
                if directory.resolve(strict=True).parent != run_root:
                    raise _run_not_found(run_id)
            except (OSError, RuntimeError):
                raise _run_not_found(run_id) from None
        return roots

    def _validated_ephemeral_root(self, *, require_exists: bool) -> Path | None:
        root = self._ephemeral_root
        if root.is_symlink():
            raise _cleanup_failure()
        try:
            if not root.exists():
                if require_exists:
                    raise _run_not_found()
                return None
            resolved = root.resolve(strict=True)
        except ApplicationError:
            raise
        except (OSError, RuntimeError):
            if require_exists:
                raise _run_not_found() from None
            raise _cleanup_failure() from None
        if resolved != root or not resolved.is_dir():
            if require_exists:
                raise _run_not_found()
            raise _cleanup_failure()
        return resolved

    def _remove_run_sources(self, run_id: str) -> None:
        for key in [key for key in self._sources if key[0] == run_id]:
            del self._sources[key]


def _write_new_file(directory: Path, filename: str, data: bytes) -> None:
    if Path(filename).name != filename:
        raise OSError("unsafe generated filename")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(directory, directory_flags)
    try:
        file_fd = os.open(filename, file_flags, 0o600, dir_fd=directory_fd)
        with os.fdopen(file_fd, "wb") as handle:
            handle.write(data)
    finally:
        os.close(directory_fd)


def _run_not_found(run_id: str | None = None) -> ApplicationError:
    return ApplicationError(
        ErrorCode.RUN_NOT_FOUND,
        "The requested run was not found.",
        run_id=run_id,
    )


def _cleanup_failure(run_id: str | None = None) -> ApplicationError:
    return ApplicationError(
        ErrorCode.CLEANUP_FAILURE,
        "Run cleanup could not be completed safely.",
        run_id=run_id,
    )
