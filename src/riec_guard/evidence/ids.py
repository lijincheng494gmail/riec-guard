from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import NoReturn

from pydantic import ValidationError

from riec_guard.errors import CanonicalModel
from riec_guard.evidence.models import (
    EvidenceComponent,
    EvidenceItem,
    EvidenceKind,
    EvidenceLedger,
    EvidenceSourceRef,
    EvidenceStatus,
)

_SHA256_PATTERN = re.compile(r"[a-f0-9]{64}\Z")
_EVIDENCE_ID_PATTERN = re.compile(r"EV-([A-Z0-9_]{2,16})-([A-F0-9]{12})\Z")
_IMPLEMENTATION_VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,99}\Z")
_WINDOWS_ABSOLUTE_PATTERN = re.compile(r"(?:\A|[\s\"'(=:])[A-Za-z]:[\\/]")
_UNC_PATTERN = re.compile(r"(?:\A|[\s\"'(=:])\\\\[^\\\s]+[\\/]")
_PREFIXED_POSIX_PATTERN = re.compile(r"(?:\A|[\s\"'(=:])/(?!/)")
_HOME_PATH_PATTERN = re.compile(r"(?:\A|[\s\"'(=:])~[^/\\\s]*[\\/]")
_SECRET_VALUE_PATTERNS = (
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{6,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|authorization|password|private[_-]?key|secret)"
        r"\s*[:=]\s*\S+"
    ),
    re.compile(r"(?i)-----BEGIN\s+[A-Z ]*PRIVATE KEY-----"),
)
_DIRECT_IDENTIFIER_PATTERNS = (
    re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
    re.compile(r"(?<!\d)(?:\+?\d[ .()-]?){10,15}(?!\d)"),
)

_IDENTITY_EXCLUDED_FIELDS = frozenset({"evidence_id", "created_at", "content_sha256"})
_IDENTITY_INCLUDED_FIELDS = frozenset(
    {
        "component",
        "kind",
        "status",
        "statement",
        "value",
        "unit",
        "source_refs",
        "parent_evidence_ids",
        "input_sha256",
        "contract_sha256",
        "implementation_version",
    }
)
_SENSITIVE_KEYS = frozenset(
    {
        "raw_rows",
        "raw_row",
        "row_data",
        "uploaded_rows",
        "direct_identifiers",
        "direct_identifier",
        "api_key",
        "authorization",
        "password",
        "secret",
        "private_key",
        "access_token",
        "absolute_path",
        "local_path",
        "private_root",
        "prompt",
        "rendered_prompt",
        "message_content",
        "operator_name",
        "customer_name",
        "email",
        "email_address",
        "phone",
        "phone_number",
        "social_security_number",
    }
)
_PERMITTED_AGGREGATE_KEYS = frozenset({"n_rows", "row_count", "min_rows"})
_MAX_EVIDENCE_VALUE_BYTES = 1_000_000


class EvidenceErrorCode(StrEnum):
    EVIDENCE_ID_INVALID = "EVIDENCE_ID_INVALID"
    EVIDENCE_HASH_MISMATCH = "EVIDENCE_HASH_MISMATCH"
    EVIDENCE_COMPONENT_MISMATCH = "EVIDENCE_COMPONENT_MISMATCH"
    EVIDENCE_DUPLICATE_ID = "EVIDENCE_DUPLICATE_ID"
    EVIDENCE_DUPLICATE_PARENT = "EVIDENCE_DUPLICATE_PARENT"
    EVIDENCE_SELF_PARENT = "EVIDENCE_SELF_PARENT"
    EVIDENCE_PARENT_NOT_FOUND = "EVIDENCE_PARENT_NOT_FOUND"
    EVIDENCE_GRAPH_CYCLE = "EVIDENCE_GRAPH_CYCLE"
    EVIDENCE_UNSAFE_CONTENT = "EVIDENCE_UNSAFE_CONTENT"
    EVIDENCE_SOURCE_REF_INVALID = "EVIDENCE_SOURCE_REF_INVALID"
    EVIDENCE_LEDGER_FINALIZED = "EVIDENCE_LEDGER_FINALIZED"
    EVIDENCE_RUN_MISMATCH = "EVIDENCE_RUN_MISMATCH"
    EVIDENCE_COLLISION = "EVIDENCE_COLLISION"
    EVIDENCE_SCHEMA_INVALID = "EVIDENCE_SCHEMA_INVALID"


class EvidenceError(ValueError):
    """Deterministic evidence failure whose text never echoes rejected content."""

    def __init__(self, code: EvidenceErrorCode, message: str) -> None:
        super().__init__(message[:500])
        self.code = code


class CanonicalJsonError(ValueError):
    """Raised when a value is not standards-compliant JSON-native data."""


@dataclass(frozen=True, slots=True)
class EvidenceIdentity:
    content_sha256: str
    evidence_id: str


def canonical_json_bytes(value: object) -> bytes:
    """Serialize strict JSON-native data (or a canonical artifact) deterministically."""

    try:
        native: object
        if isinstance(value, CanonicalModel):
            native = value.to_canonical_dict()
        else:
            native = value
        _validate_json_native(native)
        text = json.dumps(
            native,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return text.encode("utf-8")
    except CanonicalJsonError:
        raise
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise CanonicalJsonError("value cannot be encoded as canonical JSON") from None


def canonical_sha256(value: object) -> str:
    """Return the lowercase full SHA-256 of canonical JSON bytes."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def sha256_file(path: str | Path, *, require_single_link: bool = False) -> str:
    """Hash one regular non-symlink file exactly as stored."""

    if type(require_single_link) is not bool:
        raise CanonicalJsonError("hash link policy must be boolean")
    try:
        candidate = Path(path)
    except (TypeError, ValueError):
        raise CanonicalJsonError("hash source path is invalid") from None
    descriptor = -1
    try:
        metadata = candidate.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise CanonicalJsonError("hash source must be a regular non-symlink file")
        descriptor = os.open(
            candidate,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        opened_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_metadata.st_mode)
            or opened_metadata.st_dev != metadata.st_dev
            or opened_metadata.st_ino != metadata.st_ino
            or (require_single_link and opened_metadata.st_nlink != 1)
        ):
            raise CanonicalJsonError("hash source changed during safe open")
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
            final_metadata = os.fstat(handle.fileno())
            if (
                final_metadata.st_dev != opened_metadata.st_dev
                or final_metadata.st_ino != opened_metadata.st_ino
                or final_metadata.st_size != opened_metadata.st_size
                or final_metadata.st_mtime_ns != opened_metadata.st_mtime_ns
                or final_metadata.st_ctime_ns != opened_metadata.st_ctime_ns
                or (require_single_link and final_metadata.st_nlink != 1)
            ):
                raise CanonicalJsonError("hash source changed while being read")
        return digest.hexdigest()
    except CanonicalJsonError:
        raise
    except (OSError, ValueError):
        raise CanonicalJsonError("hash source is unavailable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def evidence_identity(item: EvidenceItem) -> EvidenceIdentity:
    """Recompute the frozen identity from every included evidence field."""

    payload = item.to_canonical_dict()
    included = {
        key: value for key, value in payload.items() if key not in _IDENTITY_EXCLUDED_FIELDS
    }
    if frozenset(included) != _IDENTITY_INCLUDED_FIELDS:
        _raise(
            EvidenceErrorCode.EVIDENCE_SCHEMA_INVALID,
            "Evidence identity payload does not match the frozen field set.",
        )
    try:
        digest = canonical_sha256(included)
    except CanonicalJsonError:
        raise EvidenceError(
            EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT,
            "Evidence identity content cannot be serialized safely.",
        ) from None
    component = item.component.value
    return EvidenceIdentity(
        content_sha256=digest,
        evidence_id=f"EV-{component}-{digest[:12].upper()}",
    )


def create_evidence_item(
    *,
    component: EvidenceComponent | str,
    kind: EvidenceKind | str,
    status: EvidenceStatus | str,
    statement: str,
    value: object,
    unit: str | None,
    source_refs: Sequence[EvidenceSourceRef | Mapping[str, object]],
    parent_evidence_ids: Sequence[str],
    input_sha256: str,
    contract_sha256: str,
    implementation_version: str,
    created_at: str,
) -> EvidenceItem:
    """Construct a canonical item and compute, rather than trust, its identity."""

    _validate_raw_json_native(value)
    try:
        serialized_value = canonical_json_bytes(value)
    except CanonicalJsonError:
        raise EvidenceError(
            EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT,
            "Evidence value cannot be serialized safely.",
        ) from None
    if len(serialized_value) > _MAX_EVIDENCE_VALUE_BYTES:
        _raise(
            EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT,
            "Evidence value exceeds the safe serialized-size limit.",
        )
    _validate_safe_evidence_value(statement)
    _validate_safe_evidence_value(value)
    if unit is not None:
        _validate_safe_evidence_value(unit)
    _validate_timestamp(created_at)
    _validate_sha256(input_sha256)
    _validate_sha256(contract_sha256)
    _validate_implementation_version(implementation_version)
    parsed_sources = _validate_source_refs(source_refs)
    parents = tuple(parent_evidence_ids)
    _validate_parent_ids(parents)

    try:
        provisional = EvidenceItem.model_validate(
            {
                "evidence_id": _placeholder_evidence_id(component),
                "content_sha256": "0" * 64,
                "component": component,
                "kind": kind,
                "status": status,
                "statement": statement,
                "value": value,
                "unit": unit,
                "source_refs": parsed_sources,
                "parent_evidence_ids": parents,
                "input_sha256": input_sha256,
                "contract_sha256": contract_sha256,
                "implementation_version": implementation_version,
                "created_at": created_at,
            }
        )
        identity = evidence_identity(provisional)
        item = provisional.model_copy(
            update={
                "evidence_id": identity.evidence_id,
                "content_sha256": identity.content_sha256,
            }
        )
    except EvidenceError:
        raise
    except (ValidationError, ValueError, TypeError):
        raise EvidenceError(
            EvidenceErrorCode.EVIDENCE_SCHEMA_INVALID,
            "Evidence item does not satisfy the canonical schema.",
        ) from None
    verify_evidence_item(item)
    return item


def verify_evidence_item(item: EvidenceItem) -> EvidenceIdentity:
    """Validate safety and recompute the full hash, ID, and embedded component."""

    try:
        payload = item.to_canonical_dict()
    except (ValueError, TypeError):
        raise EvidenceError(
            EvidenceErrorCode.EVIDENCE_SCHEMA_INVALID,
            "Evidence item does not satisfy the canonical schema.",
        ) from None
    _validate_item_schema(item)
    _validate_safe_evidence_value(payload["statement"])
    _validate_safe_evidence_value(payload["value"])
    try:
        serialized_value = canonical_json_bytes(payload["value"])
    except CanonicalJsonError:
        raise EvidenceError(
            EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT,
            "Evidence value cannot be serialized safely.",
        ) from None
    if len(serialized_value) > _MAX_EVIDENCE_VALUE_BYTES:
        _raise(
            EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT,
            "Evidence value exceeds the safe serialized-size limit.",
        )
    if payload["unit"] is not None:
        _validate_safe_evidence_value(payload["unit"])
    _validate_timestamp(item.created_at)
    _validate_sha256(item.input_sha256)
    _validate_sha256(item.contract_sha256)
    _validate_implementation_version(item.implementation_version)
    _validate_source_refs(item.source_refs)
    _validate_parent_ids(item.parent_evidence_ids, evidence_id=item.evidence_id)

    match = _EVIDENCE_ID_PATTERN.fullmatch(item.evidence_id)
    if match is None:
        _raise(EvidenceErrorCode.EVIDENCE_ID_INVALID, "Evidence ID is malformed.")
    if match.group(1) != item.component.value:
        _raise(
            EvidenceErrorCode.EVIDENCE_COMPONENT_MISMATCH,
            "Evidence ID component does not match the item component.",
        )
    identity = evidence_identity(item)
    if item.content_sha256 != identity.content_sha256:
        _raise(
            EvidenceErrorCode.EVIDENCE_HASH_MISMATCH,
            "Evidence content hash does not match recomputed canonical content.",
        )
    if item.evidence_id != identity.evidence_id:
        _raise(
            EvidenceErrorCode.EVIDENCE_ID_INVALID,
            "Evidence ID does not match recomputed canonical content.",
        )
    return identity


def validate_safe_evidence_content(value: object) -> None:
    """Public conservative safety check for bounded evidence metadata."""

    _validate_safe_evidence_value(value)


def _validate_json_native(
    value: object,
    *,
    depth: int = 0,
    active_containers: set[int] | None = None,
) -> None:
    if depth > 100:
        raise CanonicalJsonError("canonical JSON exceeds the safe nesting limit")
    if value is None or type(value) in {str, bool, int}:
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise CanonicalJsonError("canonical JSON numbers must be finite")
        return
    if type(value) is list:
        active = active_containers if active_containers is not None else set()
        identity = id(value)
        if identity in active:
            raise CanonicalJsonError("canonical JSON cannot contain reference cycles")
        active.add(identity)
        try:
            for item in value:
                _validate_json_native(
                    item,
                    depth=depth + 1,
                    active_containers=active,
                )
        finally:
            active.remove(identity)
        return
    if type(value) is dict:
        active = active_containers if active_containers is not None else set()
        identity = id(value)
        if identity in active:
            raise CanonicalJsonError("canonical JSON cannot contain reference cycles")
        active.add(identity)
        try:
            for key, item in value.items():
                if type(key) is not str:
                    raise CanonicalJsonError("canonical JSON object keys must be strings")
                _validate_json_native(
                    item,
                    depth=depth + 1,
                    active_containers=active,
                )
        finally:
            active.remove(identity)
        return
    raise CanonicalJsonError("canonical JSON accepts JSON-native values only")


def _validate_raw_json_native(value: object, *, depth: int = 0) -> None:
    if depth > 30:
        _raise(
            EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT,
            "Evidence value exceeds the safe nesting limit.",
        )
    if value is None or type(value) in {str, bool, int}:
        return
    if type(value) is float:
        if not math.isfinite(value):
            _raise(
                EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT,
                "Evidence value contains a non-finite number.",
            )
        return
    if type(value) is list:
        for child in value:
            _validate_raw_json_native(child, depth=depth + 1)
        return
    if type(value) is dict:
        for key, child in value.items():
            if type(key) is not str:
                _raise(
                    EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT,
                    "Evidence value contains a non-string object key.",
                )
            _validate_raw_json_native(child, depth=depth + 1)
        return
    _raise(
        EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT,
        "Evidence value is not JSON-native.",
    )


def _validate_safe_evidence_value(value: object, *, depth: int = 0) -> None:
    if depth > 30:
        _raise(
            EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT,
            "Evidence metadata exceeds the safe nesting limit.",
        )
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            _raise(
                EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT,
                "Evidence metadata contains a non-finite number.",
            )
        return
    if isinstance(value, str):
        if (
            len(value) > 3000
            or _contains_control(value)
            or _contains_secret(value)
            or _contains_direct_identifier(value)
            or _contains_absolute_path(value)
        ):
            _raise(
                EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT,
                "Evidence metadata contains unsafe content.",
            )
        return
    if isinstance(value, Mapping):
        if len(value) > 1000:
            _raise(
                EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT,
                "Evidence metadata exceeds the safe object limit.",
            )
        for key, child in value.items():
            if (
                not isinstance(key, str)
                or len(key) > 200
                or _contains_control(key)
                or _is_sensitive_key(key)
                or _contains_secret(key)
                or _contains_direct_identifier(key)
                or _contains_absolute_path(key)
            ):
                _raise(
                    EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT,
                    "Evidence metadata contains a prohibited field.",
                )
            _validate_safe_evidence_value(child, depth=depth + 1)
        return
    if isinstance(value, (list, tuple)):
        if len(value) > 1000:
            _raise(
                EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT,
                "Evidence metadata exceeds the safe array limit.",
            )
        for child in value:
            _validate_safe_evidence_value(child, depth=depth + 1)
        return
    _raise(
        EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT,
        "Evidence metadata is not JSON-native.",
    )


def _validate_source_refs(
    source_refs: Sequence[EvidenceSourceRef | Mapping[str, object]],
) -> tuple[EvidenceSourceRef, ...]:
    if len(source_refs) > 20:
        _raise(
            EvidenceErrorCode.EVIDENCE_SOURCE_REF_INVALID,
            "Evidence source-reference count exceeds the canonical limit.",
        )
    parsed: list[EvidenceSourceRef] = []
    artifact_ids: set[str] = set()
    for source_ref in source_refs:
        try:
            item = (
                source_ref
                if isinstance(source_ref, EvidenceSourceRef)
                else EvidenceSourceRef.model_validate(source_ref)
            )
        except (ValidationError, ValueError, TypeError):
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_SOURCE_REF_INVALID,
                "Evidence source reference is invalid.",
            ) from None
        if item.artifact_id in artifact_ids:
            _raise(
                EvidenceErrorCode.EVIDENCE_SOURCE_REF_INVALID,
                "Evidence source references contain a duplicate artifact identity.",
            )
        artifact_ids.add(item.artifact_id)
        if (
            _contains_control(item.artifact_id)
            or _contains_secret(item.artifact_id)
            or _contains_direct_identifier(item.artifact_id)
            or _contains_absolute_path(item.artifact_id)
        ):
            _raise(
                EvidenceErrorCode.EVIDENCE_SOURCE_REF_INVALID,
                "Evidence source artifact identity is unsafe.",
            )
        _validate_sha256(item.artifact_sha256, source_ref=True)
        if item.locator is not None:
            if (
                _contains_control(item.locator)
                or _contains_secret(item.locator)
                or _contains_direct_identifier(item.locator)
                or _contains_absolute_path(item.locator)
                or _contains_traversal(item.locator)
            ):
                _raise(
                    EvidenceErrorCode.EVIDENCE_SOURCE_REF_INVALID,
                    "Evidence source locator is unsafe.",
                )
        parsed.append(item)
    return tuple(parsed)


def _validate_parent_ids(
    parent_ids: Sequence[str],
    *,
    evidence_id: str | None = None,
) -> None:
    if len(parent_ids) > 100:
        _raise(
            EvidenceErrorCode.EVIDENCE_SCHEMA_INVALID,
            "Evidence parent count exceeds the canonical limit.",
        )
    seen: set[str] = set()
    for parent_id in parent_ids:
        if not isinstance(parent_id, str) or _EVIDENCE_ID_PATTERN.fullmatch(parent_id) is None:
            _raise(
                EvidenceErrorCode.EVIDENCE_ID_INVALID,
                "Evidence parent ID is malformed.",
            )
        if parent_id in seen:
            _raise(
                EvidenceErrorCode.EVIDENCE_DUPLICATE_PARENT,
                "Evidence parent links contain a duplicate edge.",
            )
        if evidence_id is not None and parent_id == evidence_id:
            _raise(
                EvidenceErrorCode.EVIDENCE_SELF_PARENT,
                "Evidence item cannot parent itself.",
            )
        seen.add(parent_id)


def _placeholder_evidence_id(component: EvidenceComponent | str) -> str:
    raw = component.value if isinstance(component, EvidenceComponent) else component
    if not isinstance(raw, str) or re.fullmatch(r"[A-Z0-9_]{2,16}", raw) is None:
        _raise(
            EvidenceErrorCode.EVIDENCE_COMPONENT_MISMATCH,
            "Evidence component is unsupported.",
        )
    return f"EV-{raw}-{'0' * 12}"


def _validate_sha256(value: str, *, source_ref: bool = False) -> None:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        code = (
            EvidenceErrorCode.EVIDENCE_SOURCE_REF_INVALID
            if source_ref
            else EvidenceErrorCode.EVIDENCE_SCHEMA_INVALID
        )
        _raise(code, "Evidence SHA-256 value is malformed.")


def _validate_timestamp(value: str) -> None:
    if not isinstance(value, str):
        _raise(
            EvidenceErrorCode.EVIDENCE_SCHEMA_INVALID,
            "Evidence timestamp must be an RFC 3339 string.",
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise EvidenceError(
            EvidenceErrorCode.EVIDENCE_SCHEMA_INVALID,
            "Evidence timestamp must be an RFC 3339 string.",
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _raise(
            EvidenceErrorCode.EVIDENCE_SCHEMA_INVALID,
            "Evidence timestamp must include a timezone.",
        )


def _validate_implementation_version(value: str) -> None:
    if (
        not isinstance(value, str)
        or _IMPLEMENTATION_VERSION_PATTERN.fullmatch(value) is None
        or _contains_secret(value)
        or _contains_direct_identifier(value)
        or _contains_absolute_path(value)
    ):
        _raise(
            EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT,
            "Evidence implementation version is unsafe.",
        )


def _validate_item_schema(item: EvidenceItem) -> None:
    try:
        EvidenceLedger.model_validate(
            {
                "schema_version": "1.0.0",
                "run_id": "RUN-000000000000",
                "canonicalization": {
                    "json_encoding": "utf-8",
                    "sort_keys": True,
                    "excluded_fields": ["evidence_id", "created_at", "content_sha256"],
                    "hash_algorithm": "sha256",
                    "id_format": "EV-<COMPONENT>-<FIRST12_UPPER_HEX>",
                },
                "items": [item.to_canonical_dict()],
            }
        )
    except (ValidationError, ValueError, TypeError):
        raise EvidenceError(
            EvidenceErrorCode.EVIDENCE_SCHEMA_INVALID,
            "Evidence item does not satisfy the canonical ledger schema.",
        ) from None


def _is_sensitive_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")
    if normalized in _PERMITTED_AGGREGATE_KEYS:
        return False
    if normalized in _SENSITIVE_KEYS:
        return True
    return (
        normalized in {"rows", "records", "raw_data", "uploaded_data"}
        or normalized.startswith(
            (
                "raw_row_",
                "raw_rows_",
                "uploaded_row_",
                "uploaded_rows_",
                "direct_identifier_",
                "direct_identifiers_",
                "row_data_",
                "raw_data_",
                "uploaded_data_",
            )
        )
        or normalized.endswith(
            ("_api_key", "_password", "_access_token", "_private_key", "_secret", "_prompt")
        )
    )


def _contains_control(value: str) -> bool:
    return any(ord(character) < 32 and character not in "\t\n\r" for character in value)


def _contains_secret(value: str) -> bool:
    return any(pattern.search(value) is not None for pattern in _SECRET_VALUE_PATTERNS)


def _contains_direct_identifier(value: str) -> bool:
    return any(pattern.search(value) is not None for pattern in _DIRECT_IDENTIFIER_PATTERNS)


def _contains_absolute_path(value: str) -> bool:
    if (
        _WINDOWS_ABSOLUTE_PATTERN.search(value)
        or _UNC_PATTERN.search(value)
        or _PREFIXED_POSIX_PATTERN.search(value)
        or _HOME_PATH_PATTERN.search(value)
        or "file:/" in value.casefold()
    ):
        return True
    for token in re.split(r"[\s\"'()=,;]+", value):
        candidate = token.rstrip(".:]")
        if (
            candidate.startswith(("/", "~/", "~\\", "../", "..\\", "./", ".\\"))
            or "/../" in candidate
            or "\\..\\" in candidate
        ):
            return True
    return False


def _contains_traversal(value: str) -> bool:
    if "://" in value:
        return True
    return any(part == ".." for part in re.split(r"[\\/]", value))


def _raise(code: EvidenceErrorCode, message: str) -> NoReturn:
    raise EvidenceError(code, message)


__all__ = [
    "CanonicalJsonError",
    "EvidenceError",
    "EvidenceErrorCode",
    "EvidenceIdentity",
    "canonical_json_bytes",
    "canonical_sha256",
    "create_evidence_item",
    "evidence_identity",
    "sha256_file",
    "validate_safe_evidence_content",
    "verify_evidence_item",
]
