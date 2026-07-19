from __future__ import annotations

import hashlib
import hmac
import os
import platform as platform_module
import re
import secrets
import stat
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import NoReturn, TypeVar

from pydantic import ValidationError

from riec_guard.evidence.ids import CanonicalJsonError, canonical_sha256, sha256_file
from riec_guard.riec.registry import RunRegistrySnapshot
from riec_guard.telemetry.models import (
    CodeProvenance,
    EnvironmentProvenance,
    FallbackRecord,
    GptCallRecord,
    GptCallStatus,
    GptTelemetry,
    ManifestArtifact,
    ManifestContract,
    ManifestInput,
    ManifestPrivacy,
    ManifestRandomness,
    ManifestRegistries,
    ManifestStorageRootClass,
    RunManifest,
    RunMode,
    RunStatus,
)

_RUN_ID_PATTERN = re.compile(r"RUN-[A-F0-9]{12}\Z")
_RUNTIME_RUN_ID_PATTERN = re.compile(r"RUN-([a-f0-9]{32})\Z")
_CONTRACT_ID_PATTERN = re.compile(r"AC-[A-F0-9]{12}\Z")
_ARTIFACT_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{2,127}\Z")
_SHA256_PATTERN = re.compile(r"[a-f0-9]{64}\Z")
_SEMVER_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
_COMMIT_PATTERN = re.compile(r"[a-f0-9]{7,40}\Z")
_SAFE_VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,99}\Z")
_SAFE_REQUEST_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_SAFE_ERROR_CLASS_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,199}\Z")
_MEDIA_TYPE_PATTERN = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}\Z"
)
_CHECKSUM_LINE_PATTERN = re.compile(r"([a-f0-9]{64})  ([^\r\n]+)\Z")
_WINDOWS_ABSOLUTE_PATTERN = re.compile(r"(?:\A|[\s\"'(=:])[A-Za-z]:[\\/]")
_UNC_PATTERN = re.compile(r"(?:\A|[\s\"'(=:])\\\\[^\\\s]+[\\/]")
_PREFIXED_POSIX_PATTERN = re.compile(r"(?:\A|[\s\"'(=:])/(?!/)")
_HOME_PATH_PATTERN = re.compile(r"(?:\A|[\s\"'(=:])~[^/\\\s]*[\\/]")
_SECRET_PATTERNS = (
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
_PROHIBITED_METADATA_KEYS = frozenset(
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
        "prompt",
        "rendered_prompt",
        "message_content",
        "tool_payload_rows",
        "policy_document_contents",
        "raw_response_body",
        "stack_trace",
        "exception_repr",
        "absolute_path",
        "local_path",
        "private_root",
    }
)
_TERMINAL_STATUSES = frozenset(
    {
        RunStatus.COMPLETED,
        RunStatus.COMPLETED_WITH_WARNINGS,
        RunStatus.FAILED,
    }
)
_LIFECYCLE_TRANSITION_AUTHORITY = object()
_MAX_CHECKSUM_ENTRIES = 200
_MAX_CHECKSUM_BYTES = 120_000
CHECKSUM_INVENTORY_PATH = "artifact_checksums.sha256"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class ManifestErrorCode(StrEnum):
    MANIFEST_SCHEMA_INVALID = "MANIFEST_SCHEMA_INVALID"
    MANIFEST_INVALID_TRANSITION = "MANIFEST_INVALID_TRANSITION"
    MANIFEST_TIMESTAMP_INVALID = "MANIFEST_TIMESTAMP_INVALID"
    MANIFEST_MODE_PRIVACY_MISMATCH = "MANIFEST_MODE_PRIVACY_MISMATCH"
    MANIFEST_INPUT_INVALID = "MANIFEST_INPUT_INVALID"
    MANIFEST_CONTRACT_INVALID = "MANIFEST_CONTRACT_INVALID"
    MANIFEST_REGISTRY_INVALID = "MANIFEST_REGISTRY_INVALID"
    MANIFEST_RANDOMNESS_INVALID = "MANIFEST_RANDOMNESS_INVALID"
    MANIFEST_GPT_INVALID = "MANIFEST_GPT_INVALID"
    MANIFEST_SECRET_CONTENT = "MANIFEST_SECRET_CONTENT"
    MANIFEST_ABSOLUTE_PATH = "MANIFEST_ABSOLUTE_PATH"
    MANIFEST_NOT_TERMINAL = "MANIFEST_NOT_TERMINAL"
    MANIFEST_ARTIFACT_REQUIRED = "MANIFEST_ARTIFACT_REQUIRED"
    ARTIFACT_ID_DUPLICATE = "ARTIFACT_ID_DUPLICATE"
    ARTIFACT_PATH_DUPLICATE = "ARTIFACT_PATH_DUPLICATE"
    ARTIFACT_PATH_UNSAFE = "ARTIFACT_PATH_UNSAFE"
    ARTIFACT_NOT_FOUND = "ARTIFACT_NOT_FOUND"
    ARTIFACT_SYMLINK_ESCAPE = "ARTIFACT_SYMLINK_ESCAPE"
    ARTIFACT_HASH_MISMATCH = "ARTIFACT_HASH_MISMATCH"
    ARTIFACT_NOT_PUBLIC_SAFE = "ARTIFACT_NOT_PUBLIC_SAFE"
    CHECKSUM_FORMAT_INVALID = "CHECKSUM_FORMAT_INVALID"
    CHECKSUM_DUPLICATE_PATH = "CHECKSUM_DUPLICATE_PATH"
    CHECKSUM_SELF_REFERENCE = "CHECKSUM_SELF_REFERENCE"
    CHECKSUM_VERIFICATION_FAILED = "CHECKSUM_VERIFICATION_FAILED"


class ManifestError(ValueError):
    """Safe deterministic manifest failure with a stable public code."""

    def __init__(self, code: ManifestErrorCode, message: str) -> None:
        super().__init__(message[:500])
        self.code = code


class _LifecycleTransitionKind(StrEnum):
    INITIALIZE = "initialize"
    START = "start"
    COMPLETE = "complete"
    COMPLETE_WITH_WARNINGS = "complete_with_warnings"
    FAIL = "fail"


@dataclass(frozen=True, slots=True)
class _LifecycleEvent:
    sequence: int
    from_status: RunStatus
    to_status: RunStatus
    transition_timestamp: str
    transition_kind: _LifecycleTransitionKind
    previous_witness: str
    witness: str


@dataclass(frozen=True, slots=True)
class _RegistryBinding:
    snapshot: RunRegistrySnapshot
    action_engine_version: str
    expected_registries: ManifestRegistries
    witness: str


@dataclass(frozen=True, slots=True)
class ArtifactVerificationResult:
    artifact_count: int
    verified_artifact_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ChecksumEntry:
    sha256: str
    path: str


@dataclass(frozen=True, slots=True)
class ChecksumInventory:
    relative_path: str
    content: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class ChecksumVerificationResult:
    entry_count: int
    verified_paths: tuple[str, ...]
    inventory_sha256: str


@dataclass(frozen=True, slots=True)
class ManifestVerificationResult:
    manifest_sha256: str
    artifact_verification: ArtifactVerificationResult


@dataclass(frozen=True, slots=True)
class ManifestFinalizationResult:
    manifest: RunManifest
    manifest_sha256: str
    artifact_verification: ArtifactVerificationResult


ModelT = TypeVar("ModelT")


class RunManifestBuilder:
    """Validated mutable assembly boundary whose output is a frozen canonical manifest."""

    def __init__(
        self,
        *,
        run_id: str,
        mode: RunMode | str,
        started_at: str,
        code: CodeProvenance | Mapping[str, object],
        environment: EnvironmentProvenance | Mapping[str, object],
        contract: ManifestContract | Mapping[str, object],
        registry_snapshot: RunRegistrySnapshot,
        action_engine_version: str,
        randomness: ManifestRandomness | Mapping[str, object],
        configured_model: str,
        artifact_root: Path,
        storage_root_class: ManifestStorageRootClass | str,
        registries: ManifestRegistries | Mapping[str, object] | None = None,
        release_scan_passed: bool = False,
        api: str = "responses",
        store: bool = False,
        raw_rows_sent_to_gpt: bool = False,
        direct_identifiers_sent_to_gpt: bool = False,
    ) -> None:
        _validate_run_id(run_id)
        _validate_timestamp(started_at)
        self._run_id = run_id
        self._mode = _coerce_enum(RunMode, mode, ManifestErrorCode.MANIFEST_MODE_PRIVACY_MISMATCH)
        self._started_at = started_at
        self._finished_at: str | None = None
        self._status = RunStatus.CREATED
        self._lifecycle_key = secrets.token_bytes(32)
        self._lifecycle_events: tuple[_LifecycleEvent, ...] = (
            _create_lifecycle_event(
                key=self._lifecycle_key,
                run_id=run_id,
                started_at=started_at,
                sequence=0,
                from_status=RunStatus.CREATED,
                to_status=RunStatus.CREATED,
                transition_timestamp=started_at,
                transition_kind=_LifecycleTransitionKind.INITIALIZE,
                previous_witness="0" * 64,
            ),
        )
        self._code = _coerce_model(CodeProvenance, code, ManifestErrorCode.MANIFEST_SCHEMA_INVALID)
        self._environment = _coerce_model(
            EnvironmentProvenance, environment, ManifestErrorCode.MANIFEST_SCHEMA_INVALID
        )
        self._contract = _coerce_model(
            ManifestContract, contract, ManifestErrorCode.MANIFEST_CONTRACT_INVALID
        )
        expected_registries = manifest_registries_from_snapshot(
            registry_snapshot,
            action_engine_version=action_engine_version,
        )
        self._registry_binding_key = secrets.token_bytes(32)
        self._registry_binding = _create_registry_binding(
            key=self._registry_binding_key,
            snapshot=registry_snapshot,
            action_engine_version=action_engine_version,
            expected_registries=expected_registries,
        )
        self._registries = (
            expected_registries
            if registries is None
            else _coerce_model(
                ManifestRegistries,
                registries,
                ManifestErrorCode.MANIFEST_REGISTRY_INVALID,
            )
        )
        self._randomness = _coerce_model(
            ManifestRandomness, randomness, ManifestErrorCode.MANIFEST_RANDOMNESS_INVALID
        )
        self._configured_model = _validate_safe_short_string(
            configured_model,
            maximum=100,
            code=ManifestErrorCode.MANIFEST_GPT_INVALID,
        )
        if api != "responses" or store is not False:
            _raise(
                ManifestErrorCode.MANIFEST_GPT_INVALID,
                "Manifest GPT API must be Responses with storage disabled.",
            )
        if raw_rows_sent_to_gpt is not False or direct_identifiers_sent_to_gpt is not False:
            _raise(
                ManifestErrorCode.MANIFEST_MODE_PRIVACY_MISMATCH,
                "Manifest privacy flags must prohibit raw rows and direct identifiers.",
            )
        if type(release_scan_passed) is not bool:
            _raise(
                ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
                "Release-scan result must be an explicit boolean.",
            )
        self._storage_root_class = _coerce_enum(
            ManifestStorageRootClass,
            storage_root_class,
            ManifestErrorCode.MANIFEST_MODE_PRIVACY_MISMATCH,
        )
        self._release_scan_passed = release_scan_passed
        self._artifact_root = _validate_artifact_root(artifact_root, expected_run_id=run_id)
        self._inputs: list[ManifestInput] = []
        self._gpt_calls: list[GptCallRecord] = []
        self._artifacts: list[ManifestArtifact] = []
        self._fallbacks: list[FallbackRecord] = []
        self._final_result: ManifestFinalizationResult | None = None
        _validate_code(self._code)
        _validate_environment(self._environment)
        _validate_contract(self._contract)
        _validate_registries(self._registries)
        _verify_registry_binding_state(
            self._registries,
            key=self._registry_binding_key,
            binding=self._registry_binding,
        )
        _validate_randomness(self._randomness)
        _validate_mode_storage(self._mode, self._storage_root_class)

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def status(self) -> RunStatus:
        self._verify_lifecycle_witness()
        return self._status

    @property
    def finished_at(self) -> str | None:
        self._verify_lifecycle_witness()
        return self._finished_at

    @property
    def release_scan_passed(self) -> bool:
        return self._release_scan_passed

    @property
    def inputs(self) -> tuple[ManifestInput, ...]:
        return tuple(self._inputs)

    @property
    def artifacts(self) -> tuple[ManifestArtifact, ...]:
        return tuple(self._artifacts)

    def start(self) -> RunManifestBuilder:
        self._verify_lifecycle_witness()
        if self._status is RunStatus.CREATED:
            self._apply_lifecycle_transition(
                to_status=RunStatus.RUNNING,
                transition_timestamp=self._started_at,
                transition_kind=_LifecycleTransitionKind.START,
                _authority=_LIFECYCLE_TRANSITION_AUTHORITY,
            )
            return self
        if self._status is RunStatus.RUNNING:
            return self
        _raise(
            ManifestErrorCode.MANIFEST_INVALID_TRANSITION,
            "A terminal manifest cannot return to running.",
        )

    def complete(
        self,
        *,
        finished_at: str,
        with_warnings: bool = False,
    ) -> RunManifestBuilder:
        target = RunStatus.COMPLETED_WITH_WARNINGS if with_warnings else RunStatus.COMPLETED
        return self._terminal_transition(target, finished_at)

    def fail(self, *, finished_at: str) -> RunManifestBuilder:
        return self._terminal_transition(RunStatus.FAILED, finished_at)

    def register_input(
        self,
        *,
        artifact_id: str,
        sha256: str,
        classification: str,
        row_count: int | None,
    ) -> ManifestInput:
        self._ensure_mutable()
        if len(self._inputs) >= 20:
            _raise(
                ManifestErrorCode.MANIFEST_INPUT_INVALID,
                "Manifest input count exceeds the canonical limit.",
            )
        _validate_artifact_id(artifact_id, ManifestErrorCode.MANIFEST_INPUT_INVALID)
        _validate_sha256(sha256, ManifestErrorCode.MANIFEST_INPUT_INVALID)
        if row_count is not None and (type(row_count) is not int or row_count < 0):
            _raise(
                ManifestErrorCode.MANIFEST_INPUT_INVALID,
                "Manifest input row count must be nonnegative or null.",
            )
        try:
            item = ManifestInput.model_validate(
                {
                    "artifact_id": artifact_id,
                    "sha256": sha256,
                    "classification": classification,
                    "row_count": row_count,
                }
            )
        except (ValidationError, ValueError, TypeError):
            raise ManifestError(
                ManifestErrorCode.MANIFEST_INPUT_INVALID,
                "Manifest input does not satisfy its canonical contract.",
            ) from None
        existing = next((entry for entry in self._inputs if entry.artifact_id == artifact_id), None)
        if existing is not None:
            if existing == item:
                return existing
            _raise(
                ManifestErrorCode.MANIFEST_INPUT_INVALID,
                "Manifest input identity is duplicated with different content.",
            )
        self._inputs.append(item)
        return item

    def register_gpt_call(
        self,
        *,
        purpose: str,
        status: str,
        request_id: str | None,
        model: str | None,
        latency_ms: int | None,
        input_tokens: int | None,
        output_tokens: int | None,
        fallback_used: bool,
        error_class: str | None,
    ) -> GptCallRecord:
        self._ensure_mutable()
        if len(self._gpt_calls) >= 20:
            _raise(
                ManifestErrorCode.MANIFEST_GPT_INVALID,
                "Manifest GPT call count exceeds the canonical limit.",
            )
        _validate_gpt_scalar_fields(
            status=status,
            request_id=request_id,
            model=model,
            latency_ms=latency_ms,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            fallback_used=fallback_used,
            error_class=error_class,
        )
        try:
            record = GptCallRecord.model_validate(
                {
                    "purpose": purpose,
                    "status": status,
                    "request_id": request_id,
                    "model": model,
                    "latency_ms": latency_ms,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "fallback_used": fallback_used,
                    "error_class": error_class,
                }
            )
        except (ValidationError, ValueError, TypeError):
            raise ManifestError(
                ManifestErrorCode.MANIFEST_GPT_INVALID,
                "GPT telemetry does not satisfy its canonical contract.",
            ) from None
        _validate_gpt_record(record)
        self._gpt_calls.append(record)
        return record

    def register_fallback(
        self,
        *,
        component: str,
        trigger: str,
        fallback: str,
        honesty_label: str,
    ) -> FallbackRecord:
        self._ensure_mutable()
        if len(self._fallbacks) >= 50:
            _raise(
                ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
                "Manifest fallback count exceeds the canonical limit.",
            )
        for value, maximum in (
            (component, 100),
            (trigger, 500),
            (fallback, 500),
            (honesty_label, 500),
        ):
            _validate_safe_short_string(
                value,
                maximum=maximum,
                code=ManifestErrorCode.MANIFEST_SECRET_CONTENT,
            )
        try:
            record = FallbackRecord.model_validate(
                {
                    "component": component,
                    "trigger": trigger,
                    "fallback": fallback,
                    "honesty_label": honesty_label,
                }
            )
        except (ValidationError, ValueError, TypeError):
            raise ManifestError(
                ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
                "Manifest fallback does not satisfy its canonical contract.",
            ) from None
        if record in self._fallbacks:
            return record
        self._fallbacks.append(record)
        return record

    def register_artifact(
        self,
        *,
        artifact_id: str,
        relative_path: str,
        media_type: str,
        public_safe: bool,
    ) -> ManifestArtifact:
        self._ensure_mutable()
        if len(self._artifacts) >= 200:
            _raise(
                ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
                "Manifest artifact count exceeds the canonical limit.",
            )
        _validate_artifact_id(artifact_id, ManifestErrorCode.MANIFEST_SCHEMA_INVALID)
        normalized_path = _validate_relative_artifact_path(relative_path)
        if not isinstance(media_type, str) or _MEDIA_TYPE_PATTERN.fullmatch(media_type) is None:
            _raise(
                ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
                "Artifact media type is invalid.",
            )
        if type(public_safe) is not bool:
            _raise(
                ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
                "Artifact public-safe marker must be a boolean.",
            )
        resolved = _resolve_artifact_file(self._artifact_root, normalized_path)
        digest = _safe_sha256_file(
            resolved,
            ManifestErrorCode.ARTIFACT_NOT_FOUND,
            require_single_link=True,
        )

        existing_id = next(
            (item for item in self._artifacts if item.artifact_id == artifact_id), None
        )
        if existing_id is not None:
            if existing_id.path == normalized_path:
                if (
                    _safe_sha256_file(
                        resolved,
                        ManifestErrorCode.ARTIFACT_NOT_FOUND,
                        require_single_link=True,
                    )
                    != existing_id.sha256
                ):
                    _raise(
                        ManifestErrorCode.ARTIFACT_HASH_MISMATCH,
                        "Registered artifact bytes changed after registration.",
                    )
                if (
                    existing_id.sha256 == digest
                    and existing_id.media_type == media_type
                    and existing_id.public_safe is public_safe
                ):
                    return existing_id
            _raise(
                ManifestErrorCode.ARTIFACT_ID_DUPLICATE,
                "Artifact ID is already registered with different metadata.",
            )
        if any(item.path == normalized_path for item in self._artifacts):
            _raise(
                ManifestErrorCode.ARTIFACT_PATH_DUPLICATE,
                "Artifact path is already registered under a different ID.",
            )
        try:
            artifact = ManifestArtifact.model_validate(
                {
                    "artifact_id": artifact_id,
                    "path": normalized_path,
                    "sha256": digest,
                    "media_type": media_type,
                    "public_safe": public_safe,
                }
            )
        except (ValidationError, ValueError, TypeError):
            raise ManifestError(
                ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
                "Artifact metadata does not satisfy its canonical contract.",
            ) from None
        self._artifacts.append(artifact)
        return artifact

    def finalize(self) -> ManifestFinalizationResult:
        self._verify_lifecycle_witness()
        _verify_registry_binding_state(
            self._registries,
            key=self._registry_binding_key,
            binding=self._registry_binding,
        )
        if self._final_result is not None:
            verified = verify_manifest(
                self._final_result.manifest,
                artifact_root=self._artifact_root,
                expected_registry_snapshot=self._registry_binding.snapshot,
                expected_action_engine_version=self._registry_binding.action_engine_version,
            )
            if verified.manifest_sha256 != self._final_result.manifest_sha256:
                _raise(
                    ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
                    "Finalized manifest identity changed unexpectedly.",
                )
            return self._final_result
        if self._status not in _TERMINAL_STATUSES:
            _raise(
                ManifestErrorCode.MANIFEST_NOT_TERMINAL,
                "Manifest cannot finalize before a terminal run state.",
            )
        if not self._inputs:
            _raise(
                ManifestErrorCode.MANIFEST_INPUT_INVALID,
                "Manifest finalization requires at least one input.",
            )
        if not self._artifacts:
            _raise(
                ManifestErrorCode.MANIFEST_ARTIFACT_REQUIRED,
                "Manifest finalization requires at least one artifact.",
            )
        privacy = ManifestPrivacy.model_validate(
            {
                "raw_rows_sent_to_gpt": False,
                "direct_identifiers_sent_to_gpt": False,
                "storage_root_class": self._storage_root_class,
                "release_scan_passed": self._release_scan_passed,
            }
        )
        gpt = GptTelemetry.model_validate(
            {
                "configured_model": self._configured_model,
                "api": "responses",
                "store": False,
                "calls": tuple(self._gpt_calls),
            }
        )
        _validate_gpt_fallbacks(gpt, self._fallbacks)
        try:
            manifest = RunManifest.model_validate(
                {
                    "schema_version": "1.0.0",
                    "run_id": self._run_id,
                    "mode": self._mode,
                    "started_at": self._started_at,
                    "finished_at": self._finished_at,
                    "status": self._status,
                    "code": self._code,
                    "environment": self._environment,
                    "inputs": tuple(self._inputs),
                    "contract": self._contract,
                    "registries": self._registries,
                    "randomness": self._randomness,
                    "gpt": gpt,
                    "artifacts": tuple(self._artifacts),
                    "privacy": privacy,
                    "fallbacks": tuple(self._fallbacks),
                }
            )
        except (ValidationError, ValueError, TypeError):
            raise ManifestError(
                ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
                "Run manifest does not satisfy the canonical schema.",
            ) from None
        verified = verify_manifest(
            manifest,
            artifact_root=self._artifact_root,
            expected_registry_snapshot=self._registry_binding.snapshot,
            expected_action_engine_version=self._registry_binding.action_engine_version,
        )
        self._final_result = ManifestFinalizationResult(
            manifest=manifest,
            manifest_sha256=verified.manifest_sha256,
            artifact_verification=verified.artifact_verification,
        )
        return self._final_result

    def _terminal_transition(self, target: RunStatus, finished_at: str) -> RunManifestBuilder:
        self._verify_lifecycle_witness()
        _validate_timestamp(finished_at)
        if _parse_timestamp(finished_at) < _parse_timestamp(self._started_at):
            _raise(
                ManifestErrorCode.MANIFEST_TIMESTAMP_INVALID,
                "Manifest finish time cannot precede start time.",
            )
        if self._status in _TERMINAL_STATUSES:
            if self._status is target and self._finished_at == finished_at:
                return self
            _raise(
                ManifestErrorCode.MANIFEST_INVALID_TRANSITION,
                "Terminal manifest transition cannot be changed.",
            )
        if target in {RunStatus.COMPLETED, RunStatus.COMPLETED_WITH_WARNINGS}:
            if self._status is not RunStatus.RUNNING:
                _raise(
                    ManifestErrorCode.MANIFEST_INVALID_TRANSITION,
                    "A run must be running before successful completion.",
                )
        elif target is RunStatus.FAILED and self._status not in {
            RunStatus.CREATED,
            RunStatus.RUNNING,
        }:
            _raise(
                ManifestErrorCode.MANIFEST_INVALID_TRANSITION,
                "Run failure transition is invalid.",
            )
        transition_kind = {
            RunStatus.COMPLETED: _LifecycleTransitionKind.COMPLETE,
            RunStatus.COMPLETED_WITH_WARNINGS: _LifecycleTransitionKind.COMPLETE_WITH_WARNINGS,
            RunStatus.FAILED: _LifecycleTransitionKind.FAIL,
        }[target]
        self._apply_lifecycle_transition(
            to_status=target,
            transition_timestamp=finished_at,
            transition_kind=transition_kind,
            _authority=_LIFECYCLE_TRANSITION_AUTHORITY,
        )
        return self

    def _ensure_mutable(self) -> None:
        self._verify_lifecycle_witness()
        if self._status in _TERMINAL_STATUSES or self._final_result is not None:
            _raise(
                ManifestErrorCode.MANIFEST_INVALID_TRANSITION,
                "Terminal manifest content cannot be changed.",
            )

    def _apply_lifecycle_transition(
        self,
        *,
        to_status: RunStatus,
        transition_timestamp: str,
        transition_kind: _LifecycleTransitionKind,
        _authority: object | None = None,
    ) -> None:
        self._verify_lifecycle_witness()
        if _authority is not _LIFECYCLE_TRANSITION_AUTHORITY:
            _raise_lifecycle_witness_error()
        allowed = {
            (RunStatus.CREATED, RunStatus.RUNNING): _LifecycleTransitionKind.START,
            (RunStatus.CREATED, RunStatus.FAILED): _LifecycleTransitionKind.FAIL,
            (RunStatus.RUNNING, RunStatus.COMPLETED): _LifecycleTransitionKind.COMPLETE,
            (
                RunStatus.RUNNING,
                RunStatus.COMPLETED_WITH_WARNINGS,
            ): _LifecycleTransitionKind.COMPLETE_WITH_WARNINGS,
            (RunStatus.RUNNING, RunStatus.FAILED): _LifecycleTransitionKind.FAIL,
        }
        if allowed.get((self._status, to_status)) is not transition_kind:
            _raise_lifecycle_witness_error()
        previous = self._lifecycle_events[-1]
        event = _create_lifecycle_event(
            key=self._lifecycle_key,
            run_id=self._run_id,
            started_at=self._started_at,
            sequence=len(self._lifecycle_events),
            from_status=self._status,
            to_status=to_status,
            transition_timestamp=transition_timestamp,
            transition_kind=transition_kind,
            previous_witness=previous.witness,
        )
        self._lifecycle_events = (*self._lifecycle_events, event)
        self._status = to_status
        self._finished_at = transition_timestamp if to_status in _TERMINAL_STATUSES else None

    def _verify_lifecycle_witness(self) -> None:
        _verify_lifecycle_events(
            key=self._lifecycle_key,
            run_id=self._run_id,
            started_at=self._started_at,
            events=self._lifecycle_events,
            current_status=self._status,
            current_finished_at=self._finished_at,
        )


def _create_lifecycle_event(
    *,
    key: bytes,
    run_id: str,
    started_at: str,
    sequence: int,
    from_status: RunStatus,
    to_status: RunStatus,
    transition_timestamp: str,
    transition_kind: _LifecycleTransitionKind,
    previous_witness: str,
) -> _LifecycleEvent:
    payload = "\x1f".join(
        (
            str(sequence),
            run_id,
            started_at,
            from_status.value,
            to_status.value,
            transition_timestamp,
            transition_kind.value,
            previous_witness,
        )
    ).encode("utf-8")
    witness = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return _LifecycleEvent(
        sequence=sequence,
        from_status=from_status,
        to_status=to_status,
        transition_timestamp=transition_timestamp,
        transition_kind=transition_kind,
        previous_witness=previous_witness,
        witness=witness,
    )


def _verify_lifecycle_events(
    *,
    key: bytes,
    run_id: str,
    started_at: str,
    events: object,
    current_status: object,
    current_finished_at: object,
) -> None:
    if not isinstance(key, bytes) or len(key) != 32 or not isinstance(events, tuple) or not events:
        _raise_lifecycle_witness_error()

    allowed = {
        (RunStatus.CREATED, RunStatus.RUNNING): _LifecycleTransitionKind.START,
        (RunStatus.CREATED, RunStatus.FAILED): _LifecycleTransitionKind.FAIL,
        (RunStatus.RUNNING, RunStatus.COMPLETED): _LifecycleTransitionKind.COMPLETE,
        (
            RunStatus.RUNNING,
            RunStatus.COMPLETED_WITH_WARNINGS,
        ): _LifecycleTransitionKind.COMPLETE_WITH_WARNINGS,
        (RunStatus.RUNNING, RunStatus.FAILED): _LifecycleTransitionKind.FAIL,
    }
    derived_status = RunStatus.CREATED
    derived_finished_at: str | None = None
    previous_witness = "0" * 64
    previous_timestamp = _parse_lifecycle_timestamp(started_at)

    for sequence, event in enumerate(events):
        if (
            not isinstance(event, _LifecycleEvent)
            or type(event.sequence) is not int
            or not isinstance(event.from_status, RunStatus)
            or not isinstance(event.to_status, RunStatus)
            or not isinstance(event.transition_timestamp, str)
            or not isinstance(event.transition_kind, _LifecycleTransitionKind)
            or not isinstance(event.previous_witness, str)
            or _SHA256_PATTERN.fullmatch(event.previous_witness) is None
            or not isinstance(event.witness, str)
            or _SHA256_PATTERN.fullmatch(event.witness) is None
        ):
            _raise_lifecycle_witness_error()
        expected = _create_lifecycle_event(
            key=key,
            run_id=run_id,
            started_at=started_at,
            sequence=sequence,
            from_status=event.from_status,
            to_status=event.to_status,
            transition_timestamp=event.transition_timestamp,
            transition_kind=event.transition_kind,
            previous_witness=previous_witness,
        )
        if (
            event.sequence != sequence
            or event.previous_witness != previous_witness
            or not hmac.compare_digest(event.witness, expected.witness)
        ):
            _raise_lifecycle_witness_error()

        timestamp = _parse_lifecycle_timestamp(event.transition_timestamp)
        if timestamp < previous_timestamp:
            _raise_lifecycle_witness_error()
        if sequence == 0:
            if (
                event.from_status is not RunStatus.CREATED
                or event.to_status is not RunStatus.CREATED
                or event.transition_kind is not _LifecycleTransitionKind.INITIALIZE
                or event.transition_timestamp != started_at
            ):
                _raise_lifecycle_witness_error()
        else:
            if derived_status in _TERMINAL_STATUSES:
                _raise_lifecycle_witness_error()
            expected_kind = allowed.get((derived_status, event.to_status))
            if (
                event.from_status is not derived_status
                or event.transition_kind is not expected_kind
            ):
                _raise_lifecycle_witness_error()
            derived_status = event.to_status
            if derived_status in _TERMINAL_STATUSES:
                derived_finished_at = event.transition_timestamp
        previous_timestamp = timestamp
        previous_witness = event.witness

    if current_status is not derived_status or current_finished_at != derived_finished_at:
        _raise_lifecycle_witness_error()


def _parse_lifecycle_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        _raise_lifecycle_witness_error()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _raise_lifecycle_witness_error()
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _raise_lifecycle_witness_error()
    return parsed


def _raise_lifecycle_witness_error() -> NoReturn:
    _raise(
        ManifestErrorCode.MANIFEST_INVALID_TRANSITION,
        "Manifest lifecycle transition witness is invalid.",
    )


def create_run_manifest(**fields: object) -> RunManifestBuilder:
    return RunManifestBuilder(**fields)  # type: ignore[arg-type]


def start_run(builder: RunManifestBuilder) -> RunManifestBuilder:
    return builder.start()


def complete_run(
    builder: RunManifestBuilder,
    *,
    finished_at: str,
    with_warnings: bool = False,
) -> RunManifestBuilder:
    return builder.complete(finished_at=finished_at, with_warnings=with_warnings)


def fail_run(builder: RunManifestBuilder, *, finished_at: str) -> RunManifestBuilder:
    return builder.fail(finished_at=finished_at)


def register_input(builder: RunManifestBuilder, **fields: object) -> ManifestInput:
    return builder.register_input(**fields)  # type: ignore[arg-type]


def register_gpt_call(builder: RunManifestBuilder, **fields: object) -> GptCallRecord:
    return builder.register_gpt_call(**fields)  # type: ignore[arg-type]


def register_fallback(builder: RunManifestBuilder, **fields: object) -> FallbackRecord:
    return builder.register_fallback(**fields)  # type: ignore[arg-type]


def register_artifact(builder: RunManifestBuilder, **fields: object) -> ManifestArtifact:
    return builder.register_artifact(**fields)  # type: ignore[arg-type]


def finalize_manifest(builder: RunManifestBuilder) -> ManifestFinalizationResult:
    return builder.finalize()


def manifest_sha256(manifest: RunManifest) -> str:
    """Return external identity for the complete canonical manifest without mutation."""

    serialized = manifest.to_canonical_dict()
    _validate_serialized_safety(serialized)
    return canonical_sha256(serialized)


def verify_manifest(
    manifest: RunManifest | Mapping[str, object],
    *,
    artifact_root: Path,
    expected_registry_snapshot: RunRegistrySnapshot,
    expected_action_engine_version: str,
) -> ManifestVerificationResult:
    """Strictly verify canonical content against trusted runtime registry provenance."""

    if isinstance(manifest, Mapping):
        _validate_serialized_safety(manifest)
    try:
        canonical = (
            manifest if isinstance(manifest, RunManifest) else RunManifest.model_validate(manifest)
        )
        serialized = canonical.to_canonical_dict()
    except (AttributeError, ValidationError, ValueError, TypeError):
        raise ManifestError(
            ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
            "Run manifest does not satisfy the canonical schema.",
        ) from None
    _validate_run_id(canonical.run_id)
    _validate_lifecycle(canonical)
    _validate_code(canonical.code)
    _validate_environment(canonical.environment)
    _validate_inputs(canonical.inputs)
    _validate_contract(canonical.contract)
    _validate_registries(canonical.registries)
    _validate_registry_binding(
        canonical.registries,
        expected_registry_snapshot,
        action_engine_version=expected_action_engine_version,
    )
    _validate_randomness(canonical.randomness)
    _validate_gpt(canonical.gpt)
    _validate_gpt_fallbacks(canonical.gpt, canonical.fallbacks)
    _validate_mode_privacy(canonical)
    _validate_serialized_safety(serialized)
    validated_artifact_root = _validate_artifact_root(
        artifact_root, expected_run_id=canonical.run_id
    )
    verification = verify_registered_artifacts(validated_artifact_root, canonical.artifacts)
    if canonical.mode in {RunMode.PUBLIC_BUILTIN, RunMode.PUBLIC_UPLOAD} and any(
        not artifact.public_safe for artifact in canonical.artifacts
    ):
        _raise(
            ManifestErrorCode.ARTIFACT_NOT_PUBLIC_SAFE,
            "Public-mode manifest contains an artifact not marked public-safe.",
        )
    return ManifestVerificationResult(
        manifest_sha256=canonical_sha256(serialized),
        artifact_verification=verification,
    )


def collect_code_provenance(
    repository_root: Path,
    *,
    build_week_delta_version: str,
) -> CodeProvenance:
    """Collect only repository name, commit, dirty state, and declared build version."""

    root = _validate_repository_root(repository_root)
    repository = root.name
    if not _ARTIFACT_ID_PATTERN.fullmatch(repository):
        _raise(
            ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
            "Repository name is not safe manifest metadata.",
        )
    if not isinstance(build_week_delta_version, str) or not _SAFE_VERSION_PATTERN.fullmatch(
        build_week_delta_version
    ):
        _raise(
            ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
            "Build Week delta version is invalid.",
        )
    commit_sha = _run_git(root, ("rev-parse", "HEAD")).strip()
    if _COMMIT_PATTERN.fullmatch(commit_sha) is None:
        _raise(
            ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
            "Git commit metadata is unavailable.",
        )
    dirty = bool(_run_git(root, ("status", "--porcelain")).strip())
    return CodeProvenance.model_validate(
        {
            "repository": repository,
            "commit_sha": commit_sha,
            "dirty": dirty,
            "build_week_delta_version": build_week_delta_version,
        }
    )


def collect_environment_provenance(
    repository_root: Path,
    *,
    dependency_lock_name: str = "requirements.lock",
) -> EnvironmentProvenance:
    """Collect bounded runtime facts and the exact lock bytes, never path or lock contents."""

    root = _validate_repository_root(repository_root)
    if (
        not isinstance(dependency_lock_name, str)
        or not dependency_lock_name
        or len(dependency_lock_name) > 100
        or dependency_lock_name in {".", ".."}
        or any(ord(character) < 32 or ord(character) == 127 for character in dependency_lock_name)
        or PurePosixPath(dependency_lock_name).name != dependency_lock_name
        or PureWindowsPath(dependency_lock_name).name != dependency_lock_name
    ):
        _raise(
            ManifestErrorCode.MANIFEST_ABSOLUTE_PATH,
            "Dependency-lock identifier must be a simple repository filename.",
        )
    lock_path = root / dependency_lock_name
    digest = _safe_sha256_file(lock_path, ManifestErrorCode.MANIFEST_SCHEMA_INVALID)
    platform_summary = f"{platform_module.system()} {platform_module.machine()}"
    return EnvironmentProvenance.model_validate(
        {
            "python": platform_module.python_version(),
            "platform": platform_summary,
            "dependency_lock_sha256": digest,
        }
    )


def manifest_registries_from_snapshot(
    snapshot: RunRegistrySnapshot,
    *,
    action_engine_version: str,
) -> ManifestRegistries:
    """Map only frozen RunManifest registry fields; unrelated hashes are not invented."""

    if not isinstance(snapshot, RunRegistrySnapshot) or (
        not isinstance(action_engine_version, str)
        or _SEMVER_PATTERN.fullmatch(action_engine_version) is None
    ):
        _raise(
            ManifestErrorCode.MANIFEST_REGISTRY_INVALID,
            "Action-engine version must be semantic version metadata.",
        )
    try:
        candidate = snapshot.candidate_registry
        protocols = snapshot.protocol_registry
        protocol_versions = {entry.object_id: entry.version for entry in protocols.payload.entries}
        result = ManifestRegistries.model_validate(
            {
                "candidate_registry": {
                    "id": candidate.logical_id,
                    "version": candidate.version,
                    "sha256": candidate.canonical_json_sha256,
                },
                "protocol_versions": protocol_versions,
                "action_engine_version": action_engine_version,
            }
        )
    except (AttributeError, ValidationError, ValueError, TypeError):
        raise ManifestError(
            ManifestErrorCode.MANIFEST_REGISTRY_INVALID,
            "Registry snapshot cannot populate the frozen manifest fields.",
        ) from None
    _validate_registries(result)
    return result


def registries_from_snapshot(
    snapshot: RunRegistrySnapshot,
    *,
    action_engine_version: str,
) -> ManifestRegistries:
    """Compatibility alias for the explicit manifest registry projection."""

    return manifest_registries_from_snapshot(
        snapshot,
        action_engine_version=action_engine_version,
    )


def _validate_registry_binding(
    registries: ManifestRegistries,
    snapshot: RunRegistrySnapshot,
    *,
    action_engine_version: str,
) -> None:
    expected = manifest_registries_from_snapshot(
        snapshot,
        action_engine_version=action_engine_version,
    )
    if registries.to_canonical_dict() != expected.to_canonical_dict():
        _raise(
            ManifestErrorCode.MANIFEST_REGISTRY_INVALID,
            "Manifest registries do not match the expected immutable run snapshot.",
        )


def _create_registry_binding(
    *,
    key: bytes,
    snapshot: RunRegistrySnapshot,
    action_engine_version: str,
    expected_registries: ManifestRegistries,
) -> _RegistryBinding:
    if (
        not isinstance(key, bytes)
        or len(key) != 32
        or not isinstance(snapshot, RunRegistrySnapshot)
        or not isinstance(expected_registries, ManifestRegistries)
        or not isinstance(snapshot.combined_canonical_sha256, str)
        or _SHA256_PATTERN.fullmatch(snapshot.combined_canonical_sha256) is None
    ):
        _raise_registry_binding_error()
    projected = manifest_registries_from_snapshot(
        snapshot,
        action_engine_version=action_engine_version,
    )
    if projected.to_canonical_dict() != expected_registries.to_canonical_dict():
        _raise_registry_binding_error()
    witness = _registry_binding_witness(
        key=key,
        snapshot=snapshot,
        action_engine_version=action_engine_version,
        expected_registries=expected_registries,
    )
    return _RegistryBinding(
        snapshot=snapshot,
        action_engine_version=action_engine_version,
        expected_registries=expected_registries,
        witness=witness,
    )


def _registry_binding_witness(
    *,
    key: bytes,
    snapshot: RunRegistrySnapshot,
    action_engine_version: str,
    expected_registries: ManifestRegistries,
) -> str:
    try:
        payload_sha256 = canonical_sha256(
            {
                "snapshot_combined_canonical_sha256": snapshot.combined_canonical_sha256,
                "action_engine_version": action_engine_version,
                "manifest_registries": expected_registries.to_canonical_dict(),
            }
        )
    except (AttributeError, CanonicalJsonError, TypeError, ValueError):
        _raise_registry_binding_error()
    payload = f"run-registry-binding\x1f{payload_sha256}".encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _verify_registry_binding_state(
    registries: ManifestRegistries,
    *,
    key: object,
    binding: object,
) -> None:
    if (
        not isinstance(key, bytes)
        or len(key) != 32
        or not isinstance(binding, _RegistryBinding)
        or not isinstance(binding.witness, str)
        or _SHA256_PATTERN.fullmatch(binding.witness) is None
    ):
        _raise_registry_binding_error()
    projected = manifest_registries_from_snapshot(
        binding.snapshot,
        action_engine_version=binding.action_engine_version,
    )
    if projected.to_canonical_dict() != binding.expected_registries.to_canonical_dict():
        _raise_registry_binding_error()
    expected_witness = _registry_binding_witness(
        key=key,
        snapshot=binding.snapshot,
        action_engine_version=binding.action_engine_version,
        expected_registries=binding.expected_registries,
    )
    if not hmac.compare_digest(binding.witness, expected_witness):
        _raise_registry_binding_error()
    if registries.to_canonical_dict() != binding.expected_registries.to_canonical_dict():
        _raise_registry_binding_error()


def _raise_registry_binding_error() -> NoReturn:
    _raise(
        ManifestErrorCode.MANIFEST_REGISTRY_INVALID,
        "Manifest registries do not match the expected immutable run snapshot.",
    )


def verify_registered_artifact(
    artifact_root: Path,
    artifact: ManifestArtifact,
) -> str:
    root = _validate_artifact_root(artifact_root)
    path = _validate_relative_artifact_path(artifact.path)
    resolved = _resolve_artifact_file(root, path)
    digest = _safe_sha256_file(
        resolved,
        ManifestErrorCode.ARTIFACT_NOT_FOUND,
        require_single_link=True,
    )
    if digest != artifact.sha256:
        _raise(
            ManifestErrorCode.ARTIFACT_HASH_MISMATCH,
            "Registered artifact bytes do not match the manifest hash.",
        )
    return digest


def verify_registered_artifacts(
    artifact_root: Path,
    artifacts: Sequence[ManifestArtifact],
) -> ArtifactVerificationResult:
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for artifact in artifacts:
        if artifact.artifact_id in seen_ids:
            _raise(
                ManifestErrorCode.ARTIFACT_ID_DUPLICATE,
                "Manifest contains a duplicate artifact ID.",
            )
        path = _validate_relative_artifact_path(artifact.path)
        if path in seen_paths:
            _raise(
                ManifestErrorCode.ARTIFACT_PATH_DUPLICATE,
                "Manifest contains a duplicate artifact path.",
            )
        verify_registered_artifact(artifact_root, artifact)
        seen_ids.add(artifact.artifact_id)
        seen_paths.add(path)
    return ArtifactVerificationResult(
        artifact_count=len(artifacts),
        verified_artifact_ids=tuple(sorted(seen_ids)),
    )


def render_checksum_inventory(artifacts: Sequence[ManifestArtifact]) -> bytes:
    """Render lowercase SHA-256 lines sorted by POSIX relative path with a final newline."""

    if len(artifacts) > _MAX_CHECKSUM_ENTRIES:
        _raise(
            ManifestErrorCode.CHECKSUM_FORMAT_INVALID,
            "Checksum inventory exceeds the canonical artifact limit.",
        )
    by_path: dict[str, str] = {}
    for artifact in artifacts:
        path = _validate_relative_artifact_path(artifact.path)
        _validate_sha256(artifact.sha256, ManifestErrorCode.CHECKSUM_FORMAT_INVALID)
        if path == CHECKSUM_INVENTORY_PATH:
            _raise(
                ManifestErrorCode.CHECKSUM_SELF_REFERENCE,
                "Checksum inventory cannot list itself.",
            )
        if path in by_path:
            _raise(
                ManifestErrorCode.CHECKSUM_DUPLICATE_PATH,
                "Checksum inventory contains a duplicate path.",
            )
        by_path[path] = artifact.sha256
    if not by_path:
        _raise(
            ManifestErrorCode.CHECKSUM_FORMAT_INVALID,
            "Checksum inventory requires at least one artifact.",
        )
    return "".join(f"{by_path[path]}  {path}\n" for path in sorted(by_path)).encode("utf-8")


def parse_checksum_inventory(
    content: bytes | str,
    *,
    checksum_relative_path: str = CHECKSUM_INVENTORY_PATH,
) -> tuple[ChecksumEntry, ...]:
    checksum_path = _validate_relative_artifact_path(checksum_relative_path)
    try:
        text = content.decode("utf-8") if isinstance(content, bytes) else content
    except UnicodeDecodeError:
        raise ManifestError(
            ManifestErrorCode.CHECKSUM_FORMAT_INVALID,
            "Checksum inventory must be UTF-8 text.",
        ) from None
    if (
        not isinstance(text, str)
        or not text
        or len(text) > _MAX_CHECKSUM_BYTES
        or not text.endswith("\n")
        or "\r" in text
    ):
        _raise(
            ManifestErrorCode.CHECKSUM_FORMAT_INVALID,
            "Checksum inventory requires canonical lines and a final newline.",
        )
    entries: list[ChecksumEntry] = []
    seen: set[str] = set()
    for line in text[:-1].split("\n"):
        if len(entries) >= _MAX_CHECKSUM_ENTRIES:
            _raise(
                ManifestErrorCode.CHECKSUM_FORMAT_INVALID,
                "Checksum inventory exceeds the canonical artifact limit.",
            )
        match = _CHECKSUM_LINE_PATTERN.fullmatch(line)
        if match is None:
            _raise(
                ManifestErrorCode.CHECKSUM_FORMAT_INVALID,
                "Checksum inventory contains a malformed line.",
            )
        path = _validate_relative_artifact_path(match.group(2))
        if path == checksum_path:
            _raise(
                ManifestErrorCode.CHECKSUM_SELF_REFERENCE,
                "Checksum inventory cannot list itself.",
            )
        if path in seen:
            _raise(
                ManifestErrorCode.CHECKSUM_DUPLICATE_PATH,
                "Checksum inventory contains a duplicate path.",
            )
        seen.add(path)
        entries.append(ChecksumEntry(sha256=match.group(1), path=path))
    if tuple(entry.path for entry in entries) != tuple(sorted(seen)):
        _raise(
            ManifestErrorCode.CHECKSUM_FORMAT_INVALID,
            "Checksum inventory paths are not deterministically sorted.",
        )
    return tuple(entries)


def write_checksum_inventory(
    artifact_root: Path,
    artifacts: Sequence[ManifestArtifact],
    *,
    checksum_relative_path: str = CHECKSUM_INVENTORY_PATH,
) -> ChecksumInventory:
    root = _validate_artifact_root(artifact_root)
    relative_path = _validate_relative_artifact_path(checksum_relative_path)
    if any(artifact.path == relative_path for artifact in artifacts):
        _raise(
            ManifestErrorCode.CHECKSUM_SELF_REFERENCE,
            "Checksum inventory cannot be one of its own registered inputs.",
        )
    verify_registered_artifacts(root, artifacts)
    content = render_checksum_inventory(artifacts)
    destination = root / PurePosixPath(relative_path)
    try:
        parent_metadata = destination.parent.lstat()
        parent_resolved = destination.parent.resolve(strict=True)
    except OSError:
        raise ManifestError(
            ManifestErrorCode.CHECKSUM_FORMAT_INVALID,
            "Checksum destination parent must already exist inside the artifact root.",
        ) from None
    if stat.S_ISLNK(parent_metadata.st_mode) or not parent_resolved.is_relative_to(root):
        _raise(
            ManifestErrorCode.ARTIFACT_SYMLINK_ESCAPE,
            "Checksum destination resolves outside the artifact root.",
        )
    if not stat.S_ISDIR(parent_metadata.st_mode):
        _raise(
            ManifestErrorCode.CHECKSUM_FORMAT_INVALID,
            "Checksum destination parent must be a directory.",
        )
    current = root
    for part in PurePosixPath(relative_path).parts[:-1]:
        current /= part
        try:
            current_metadata = current.lstat()
        except OSError:
            raise ManifestError(
                ManifestErrorCode.CHECKSUM_FORMAT_INVALID,
                "Checksum destination parent must already exist inside the artifact root.",
            ) from None
        if stat.S_ISLNK(current_metadata.st_mode):
            _raise(
                ManifestErrorCode.ARTIFACT_SYMLINK_ESCAPE,
                "Checksum destination cannot traverse a symbolic-link directory.",
            )
        if not stat.S_ISDIR(current_metadata.st_mode):
            _raise(
                ManifestErrorCode.CHECKSUM_FORMAT_INVALID,
                "Checksum destination parent must be a directory.",
            )
    try:
        descriptor = _secure_create_relative_file(root, relative_path)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
    except OSError:
        raise ManifestError(
            ManifestErrorCode.CHECKSUM_FORMAT_INVALID,
            "Checksum inventory could not be written safely.",
        ) from None
    finally:
        if "descriptor" in locals() and descriptor >= 0:
            os.close(descriptor)
    try:
        digest = sha256_file(destination, require_single_link=True)
    except CanonicalJsonError:
        raise ManifestError(
            ManifestErrorCode.CHECKSUM_FORMAT_INVALID,
            "Checksum inventory could not be verified after writing.",
        ) from None
    return ChecksumInventory(relative_path=relative_path, content=content, sha256=digest)


def _secure_create_relative_file(root: Path, relative_path: str) -> int:
    """Create a new file through directory descriptors so symlink swaps cannot redirect it."""

    parts = PurePosixPath(relative_path).parts
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    root_descriptor = -1
    parent_descriptor = -1
    try:
        root_descriptor = os.open(root, directory_flags)
        parent_descriptor = root_descriptor
        for part in parts[:-1]:
            next_descriptor = os.open(
                part,
                directory_flags,
                dir_fd=parent_descriptor,
            )
            if not stat.S_ISDIR(os.fstat(next_descriptor).st_mode):
                os.close(next_descriptor)
                raise OSError
            if parent_descriptor != root_descriptor:
                os.close(parent_descriptor)
            parent_descriptor = next_descriptor
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        return os.open(parts[-1], flags, 0o600, dir_fd=parent_descriptor)
    finally:
        if parent_descriptor >= 0 and parent_descriptor != root_descriptor:
            os.close(parent_descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)


def verify_checksum_inventory(
    artifact_root: Path,
    content: bytes | str,
    artifacts: Sequence[ManifestArtifact],
    *,
    checksum_relative_path: str = CHECKSUM_INVENTORY_PATH,
) -> ChecksumVerificationResult:
    root = _validate_artifact_root(artifact_root)
    entries = parse_checksum_inventory(content, checksum_relative_path=checksum_relative_path)
    expected = {artifact.path: artifact for artifact in artifacts}
    if len(expected) != len(artifacts):
        _raise(
            ManifestErrorCode.CHECKSUM_DUPLICATE_PATH,
            "Registered artifacts contain a duplicate checksum path.",
        )
    if set(expected) != {entry.path for entry in entries}:
        _raise(
            ManifestErrorCode.CHECKSUM_VERIFICATION_FAILED,
            "Checksum inventory does not match the registered artifact set.",
        )
    for entry in entries:
        artifact = expected[entry.path]
        if entry.sha256 != artifact.sha256:
            _raise(
                ManifestErrorCode.CHECKSUM_VERIFICATION_FAILED,
                "Checksum inventory hash does not match registered metadata.",
            )
        resolved = _resolve_artifact_file(root, entry.path)
        if (
            _safe_sha256_file(
                resolved,
                ManifestErrorCode.CHECKSUM_VERIFICATION_FAILED,
                require_single_link=True,
            )
            != entry.sha256
        ):
            _raise(
                ManifestErrorCode.CHECKSUM_VERIFICATION_FAILED,
                "Artifact bytes do not match the checksum inventory.",
            )
    encoded = content.encode("utf-8") if isinstance(content, str) else content
    return ChecksumVerificationResult(
        entry_count=len(entries),
        verified_paths=tuple(entry.path for entry in entries),
        inventory_sha256=hashlib.sha256(encoded).hexdigest(),
    )


def _validate_lifecycle(manifest: RunManifest) -> None:
    started = _parse_timestamp(manifest.started_at)
    if manifest.status in _TERMINAL_STATUSES:
        if manifest.finished_at is None:
            _raise(
                ManifestErrorCode.MANIFEST_TIMESTAMP_INVALID,
                "Terminal manifest requires a finish time.",
            )
        if _parse_timestamp(manifest.finished_at) < started:
            _raise(
                ManifestErrorCode.MANIFEST_TIMESTAMP_INVALID,
                "Manifest finish time cannot precede start time.",
            )
    else:
        if manifest.finished_at is not None:
            _raise(
                ManifestErrorCode.MANIFEST_TIMESTAMP_INVALID,
                "Nonterminal manifest cannot contain a finish time.",
            )
        _raise(
            ManifestErrorCode.MANIFEST_NOT_TERMINAL,
            "Manifest verification requires a terminal run state.",
        )


def _validate_code(code: CodeProvenance) -> None:
    if (
        not isinstance(code.repository, str)
        or not code.repository
        or len(code.repository) > 300
        or _contains_unsafe_string(code.repository)
        or _COMMIT_PATTERN.fullmatch(code.commit_sha) is None
        or not isinstance(code.build_week_delta_version, str)
        or len(code.build_week_delta_version) > 50
        or _contains_unsafe_string(code.build_week_delta_version)
    ):
        _raise(
            ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
            "Manifest code provenance is invalid.",
        )


def _validate_environment(environment: EnvironmentProvenance) -> None:
    _validate_sha256(environment.dependency_lock_sha256, ManifestErrorCode.MANIFEST_SCHEMA_INVALID)
    for value, maximum in ((environment.python, 50), (environment.platform, 300)):
        _validate_safe_short_string(
            value,
            maximum=maximum,
            code=ManifestErrorCode.MANIFEST_SECRET_CONTENT,
        )


def _validate_inputs(inputs: Sequence[ManifestInput]) -> None:
    if not inputs:
        _raise(
            ManifestErrorCode.MANIFEST_INPUT_INVALID,
            "Manifest requires at least one input.",
        )
    ids: set[str] = set()
    for item in inputs:
        _validate_artifact_id(item.artifact_id, ManifestErrorCode.MANIFEST_INPUT_INVALID)
        _validate_sha256(item.sha256, ManifestErrorCode.MANIFEST_INPUT_INVALID)
        if item.artifact_id in ids:
            _raise(
                ManifestErrorCode.MANIFEST_INPUT_INVALID,
                "Manifest contains a duplicate input identity.",
            )
        ids.add(item.artifact_id)


def _validate_contract(contract: ManifestContract) -> None:
    if not contract.contract_id.startswith("AC-") or len(contract.contract_id) != 15:
        _raise(
            ManifestErrorCode.MANIFEST_CONTRACT_INVALID,
            "Manifest contract identity is malformed.",
        )
    _validate_sha256(contract.sha256, ManifestErrorCode.MANIFEST_CONTRACT_INVALID)
    _validate_safe_short_string(
        contract.schema_version,
        maximum=100,
        code=ManifestErrorCode.MANIFEST_CONTRACT_INVALID,
    )


def _validate_registries(registries: ManifestRegistries) -> None:
    candidate = registries.candidate_registry
    _validate_artifact_id(candidate.id, ManifestErrorCode.MANIFEST_REGISTRY_INVALID)
    _validate_sha256(candidate.sha256, ManifestErrorCode.MANIFEST_REGISTRY_INVALID)
    _validate_safe_short_string(
        candidate.version,
        maximum=100,
        code=ManifestErrorCode.MANIFEST_REGISTRY_INVALID,
    )
    protocol_versions = dict(registries.protocol_versions)
    if not protocol_versions:
        _raise(
            ManifestErrorCode.MANIFEST_REGISTRY_INVALID,
            "Manifest requires at least one protocol version.",
        )
    for protocol_id, version in protocol_versions.items():
        if (
            not isinstance(protocol_id, str)
            or not protocol_id
            or len(protocol_id) > 127
            or not isinstance(version, str)
            or _SEMVER_PATTERN.fullmatch(version) is None
        ):
            _raise(
                ManifestErrorCode.MANIFEST_REGISTRY_INVALID,
                "Manifest protocol version metadata is invalid.",
            )
    if _SEMVER_PATTERN.fullmatch(registries.action_engine_version) is None:
        _raise(
            ManifestErrorCode.MANIFEST_REGISTRY_INVALID,
            "Manifest action-engine version is invalid.",
        )


def _validate_randomness(randomness: ManifestRandomness) -> None:
    if (
        any(
            type(value) is not int
            for value in (
                randomness.global_seed,
                randomness.bootstrap_seed,
                randomness.bootstrap_replicates,
            )
        )
        or randomness.bootstrap_replicates < 0
    ):
        _raise(
            ManifestErrorCode.MANIFEST_RANDOMNESS_INVALID,
            "Manifest randomness metadata is invalid.",
        )


def _validate_gpt(gpt: GptTelemetry) -> None:
    if gpt.api != "responses" or gpt.store is not False:
        _raise(
            ManifestErrorCode.MANIFEST_GPT_INVALID,
            "Manifest GPT telemetry must use Responses with storage disabled.",
        )
    _validate_safe_short_string(
        gpt.configured_model,
        maximum=100,
        code=ManifestErrorCode.MANIFEST_GPT_INVALID,
    )
    for record in gpt.calls:
        _validate_gpt_record(record)


def _validate_gpt_fallbacks(
    gpt: GptTelemetry,
    fallbacks: Sequence[FallbackRecord],
) -> None:
    fallback_components = {record.component for record in fallbacks}
    for call in gpt.calls:
        if call.status is GptCallStatus.FALLBACK and call.purpose.value not in fallback_components:
            _raise(
                ManifestErrorCode.MANIFEST_GPT_INVALID,
                "GPT fallback telemetry requires a matching honesty record.",
            )


def _validate_gpt_record(record: GptCallRecord) -> None:
    _validate_gpt_scalar_fields(
        status=record.status.value,
        request_id=record.request_id,
        model=record.model,
        latency_ms=record.latency_ms,
        input_tokens=record.input_tokens,
        output_tokens=record.output_tokens,
        fallback_used=record.fallback_used,
        error_class=record.error_class,
    )


def _validate_gpt_scalar_fields(
    *,
    status: str,
    request_id: str | None,
    model: str | None,
    latency_ms: int | None,
    input_tokens: int | None,
    output_tokens: int | None,
    fallback_used: bool,
    error_class: str | None,
) -> None:
    if any(
        value is not None and (type(value) is not int or value < 0)
        for value in (latency_ms, input_tokens, output_tokens)
    ):
        _raise(
            ManifestErrorCode.MANIFEST_GPT_INVALID,
            "GPT timing and token telemetry must be nonnegative or null.",
        )
    if type(fallback_used) is not bool:
        _raise(
            ManifestErrorCode.MANIFEST_GPT_INVALID,
            "GPT fallback telemetry must be boolean.",
        )
    if request_id is not None and _SAFE_REQUEST_ID_PATTERN.fullmatch(request_id) is None:
        _raise(
            ManifestErrorCode.MANIFEST_GPT_INVALID,
            "GPT request identity is unsafe.",
        )
    if model is not None:
        _validate_safe_short_string(
            model,
            maximum=100,
            code=ManifestErrorCode.MANIFEST_GPT_INVALID,
        )
    if error_class is not None and _SAFE_ERROR_CLASS_PATTERN.fullmatch(error_class) is None:
        _raise(
            ManifestErrorCode.MANIFEST_GPT_INVALID,
            "GPT error class must be a bounded safe classification.",
        )
    try:
        call_status = GptCallStatus(status)
    except ValueError:
        raise ManifestError(
            ManifestErrorCode.MANIFEST_GPT_INVALID,
            "GPT call status is unsupported.",
        ) from None
    if call_status is GptCallStatus.NOT_CALLED:
        if (
            any(
                value is not None
                for value in (
                    request_id,
                    model,
                    latency_ms,
                    input_tokens,
                    output_tokens,
                    error_class,
                )
            )
            or fallback_used
        ):
            _raise(
                ManifestErrorCode.MANIFEST_GPT_INVALID,
                "Not-called GPT telemetry cannot claim call metadata.",
            )
    elif call_status is GptCallStatus.SUCCESS:
        if model is None or error_class is not None or fallback_used:
            _raise(
                ManifestErrorCode.MANIFEST_GPT_INVALID,
                "Successful GPT telemetry requires a model and no failure claim.",
            )
    elif call_status is GptCallStatus.FAILED:
        if error_class is None or fallback_used:
            _raise(
                ManifestErrorCode.MANIFEST_GPT_INVALID,
                "Failed GPT telemetry requires a safe error class.",
            )
    elif not fallback_used:
        _raise(
            ManifestErrorCode.MANIFEST_GPT_INVALID,
            "Fallback GPT telemetry must expose fallback use.",
        )


def _validate_mode_privacy(manifest: RunManifest) -> None:
    privacy = manifest.privacy
    if privacy.raw_rows_sent_to_gpt or privacy.direct_identifiers_sent_to_gpt:
        _raise(
            ManifestErrorCode.MANIFEST_MODE_PRIVACY_MISMATCH,
            "Manifest privacy boundary was violated.",
        )
    _validate_mode_storage(manifest.mode, privacy.storage_root_class)
    classifications = {item.classification.value for item in manifest.inputs}
    if manifest.mode is RunMode.PUBLIC_BUILTIN:
        if "public_synthetic" not in classifications or classifications - {
            "public_synthetic",
            "policy_text",
        }:
            _raise(
                ManifestErrorCode.MANIFEST_MODE_PRIVACY_MISMATCH,
                "Public built-in mode has inconsistent input classifications.",
            )
    elif manifest.mode is RunMode.PUBLIC_UPLOAD:
        if "public_upload" not in classifications or classifications - {
            "public_upload",
            "policy_text",
        }:
            _raise(
                ManifestErrorCode.MANIFEST_MODE_PRIVACY_MISMATCH,
                "Public upload mode has inconsistent input classifications.",
            )
    elif classifications - {
        "public_synthetic",
        "public_upload",
        "private_industrial",
        "policy_text",
    }:
        _raise(
            ManifestErrorCode.MANIFEST_MODE_PRIVACY_MISMATCH,
            "Local-private mode has inconsistent input classifications.",
        )


def _validate_mode_storage(
    mode: RunMode,
    storage: ManifestStorageRootClass,
) -> None:
    if mode in {RunMode.PUBLIC_BUILTIN, RunMode.PUBLIC_UPLOAD}:
        if storage is not ManifestStorageRootClass.PUBLIC_EPHEMERAL:
            _raise(
                ManifestErrorCode.MANIFEST_MODE_PRIVACY_MISMATCH,
                "Public mode requires public-ephemeral artifact storage.",
            )
    elif storage is not ManifestStorageRootClass.PRIVATE_LOCAL:
        _raise(
            ManifestErrorCode.MANIFEST_MODE_PRIVACY_MISMATCH,
            "Local-private mode requires private-local artifact storage.",
        )


def _validate_serialized_safety(
    value: object,
    *,
    depth: int = 0,
    field_name: str | None = None,
) -> None:
    if depth > 40:
        _raise(
            ManifestErrorCode.MANIFEST_SECRET_CONTENT,
            "Manifest metadata exceeds the safe nesting limit.",
        )
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, str):
        if len(value) > 10_000:
            _raise(
                ManifestErrorCode.MANIFEST_SECRET_CONTENT,
                "Manifest metadata exceeds the safe string limit.",
            )
        try:
            value.encode("utf-8")
        except UnicodeError:
            raise ManifestError(
                ManifestErrorCode.MANIFEST_SECRET_CONTENT,
                "Manifest metadata is not valid UTF-8 text.",
            ) from None
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            _raise(
                ManifestErrorCode.MANIFEST_SECRET_CONTENT,
                "Manifest metadata contains prohibited control characters.",
            )
        if _contains_absolute_path(value):
            _raise(
                ManifestErrorCode.MANIFEST_ABSOLUTE_PATH,
                "Manifest metadata contains an absolute local path.",
            )
        structured_identity = (
            (field_name == "commit_sha" and _COMMIT_PATTERN.fullmatch(value) is not None)
            or (field_name == "run_id" and _RUN_ID_PATTERN.fullmatch(value) is not None)
            or (field_name == "contract_id" and _CONTRACT_ID_PATTERN.fullmatch(value) is not None)
            or (
                field_name is not None
                and (field_name == "sha256" or field_name.endswith("_sha256"))
                and _SHA256_PATTERN.fullmatch(value) is not None
            )
        )
        if _contains_secret(value) or (
            not structured_identity and _contains_direct_identifier(value)
        ):
            _raise(
                ManifestErrorCode.MANIFEST_SECRET_CONTENT,
                "Manifest metadata contains prohibited sensitive content.",
            )
        return
    if isinstance(value, Mapping):
        if len(value) > 1000:
            _raise(
                ManifestErrorCode.MANIFEST_SECRET_CONTENT,
                "Manifest metadata exceeds the safe object limit.",
            )
        for key, child in value.items():
            if (
                not isinstance(key, str)
                or len(key) > 500
                or any(ord(character) < 32 or ord(character) == 127 for character in key)
                or _is_prohibited_metadata_key(key)
                or _contains_absolute_path(key)
                or _contains_secret(key)
                or _contains_direct_identifier(key)
            ):
                _raise(
                    ManifestErrorCode.MANIFEST_SECRET_CONTENT,
                    "Manifest metadata contains a prohibited field.",
                )
            _validate_serialized_safety(child, depth=depth + 1, field_name=key)
        return
    if isinstance(value, (list, tuple)):
        if len(value) > 1000:
            _raise(
                ManifestErrorCode.MANIFEST_SECRET_CONTENT,
                "Manifest metadata exceeds the safe array limit.",
            )
        for child in value:
            _validate_serialized_safety(
                child,
                depth=depth + 1,
                field_name=field_name,
            )
        return
    _raise(
        ManifestErrorCode.MANIFEST_SECRET_CONTENT,
        "Manifest metadata is not JSON-native.",
    )


def _validate_artifact_root(
    root: Path,
    *,
    expected_run_id: str | None = None,
) -> Path:
    if not isinstance(root, Path) or not root.is_absolute():
        _raise(
            ManifestErrorCode.ARTIFACT_PATH_UNSAFE,
            "Artifact root must be an explicit absolute run root.",
        )
    try:
        metadata = root.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            _raise(
                ManifestErrorCode.ARTIFACT_SYMLINK_ESCAPE,
                "Artifact root cannot be a symbolic link.",
            )
        resolved = root.resolve(strict=True)
        if (
            not resolved.is_dir()
            or resolved != root
            or resolved.name != "artifacts"
            or resolved == Path(resolved.anchor)
            or resolved.is_relative_to(_REPOSITORY_ROOT)
        ):
            _raise(
                ManifestErrorCode.ARTIFACT_PATH_UNSAFE,
                "Artifact root must be a dedicated run artifacts directory.",
            )
        storage_run_id = resolved.parent.name
        runtime_match = _RUNTIME_RUN_ID_PATTERN.fullmatch(storage_run_id)
        if _RUN_ID_PATTERN.fullmatch(storage_run_id) is None and runtime_match is None:
            _raise(
                ManifestErrorCode.ARTIFACT_PATH_UNSAFE,
                "Artifact root parent is not a recognized run identity.",
            )
        if expected_run_id is not None:
            _validate_run_id(expected_run_id)
            runtime_id_is_bound = (
                runtime_match is not None
                and f"RUN-{runtime_match.group(1)[:12].upper()}" == expected_run_id
            )
            if storage_run_id != expected_run_id and not runtime_id_is_bound:
                _raise(
                    ManifestErrorCode.ARTIFACT_PATH_UNSAFE,
                    "Artifact root is not bound to the manifest run identity.",
                )
        return resolved
    except ManifestError:
        raise
    except OSError:
        raise ManifestError(
            ManifestErrorCode.ARTIFACT_PATH_UNSAFE,
            "Artifact root is unavailable.",
        ) from None


def _validate_relative_artifact_path(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 500
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or "\\" in value
    ):
        _raise(
            ManifestErrorCode.ARTIFACT_PATH_UNSAFE,
            "Artifact path must be a bounded POSIX relative path.",
        )
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise ManifestError(
            ManifestErrorCode.ARTIFACT_PATH_UNSAFE,
            "Artifact path must be valid UTF-8 text.",
        ) from None
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or value.startswith("//")
        or "://" in value
        or _contains_absolute_path(value)
        or _contains_secret(value)
        or _contains_direct_identifier(value)
        or any(part in {"", ".", ".."} for part in posix.parts)
        or posix.as_posix() != value
    ):
        _raise(
            ManifestErrorCode.ARTIFACT_PATH_UNSAFE,
            "Artifact path must be a normalized POSIX relative path.",
        )
    return value


def _resolve_artifact_file(root: Path, relative_path: str) -> Path:
    root = _validate_artifact_root(root)
    path = root / PurePosixPath(_validate_relative_artifact_path(relative_path))
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        raise ManifestError(
            ManifestErrorCode.ARTIFACT_NOT_FOUND,
            "Registered artifact is missing.",
        ) from None
    except OSError:
        raise ManifestError(
            ManifestErrorCode.ARTIFACT_NOT_FOUND,
            "Registered artifact is unreadable.",
        ) from None
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise ManifestError(
            ManifestErrorCode.ARTIFACT_NOT_FOUND,
            "Registered artifact cannot be resolved safely.",
        ) from None
    if not resolved.is_relative_to(root):
        _raise(
            ManifestErrorCode.ARTIFACT_SYMLINK_ESCAPE,
            "Registered artifact resolves outside the artifact root.",
        )
    if stat.S_ISLNK(metadata.st_mode):
        _raise(
            ManifestErrorCode.ARTIFACT_PATH_UNSAFE,
            "Registered artifact cannot be a symbolic link.",
        )
    current = path.parent
    while current != root:
        try:
            if current.is_symlink():
                _raise(
                    ManifestErrorCode.ARTIFACT_PATH_UNSAFE,
                    "Registered artifact cannot traverse a symbolic-link directory.",
                )
        except OSError:
            raise ManifestError(
                ManifestErrorCode.ARTIFACT_PATH_UNSAFE,
                "Registered artifact parent is unsafe.",
            ) from None
        current = current.parent
    if not stat.S_ISREG(metadata.st_mode):
        _raise(
            ManifestErrorCode.ARTIFACT_PATH_UNSAFE,
            "Registered artifact must be a regular file.",
        )
    if metadata.st_nlink != 1:
        _raise(
            ManifestErrorCode.ARTIFACT_PATH_UNSAFE,
            "Registered artifact cannot be a hard-linked file.",
        )
    return resolved


def _validate_repository_root(root: Path) -> Path:
    if not isinstance(root, Path) or not root.is_absolute():
        _raise(
            ManifestErrorCode.MANIFEST_ABSOLUTE_PATH,
            "Repository collector requires an explicit validated root.",
        )
    try:
        if root.is_symlink():
            _raise(
                ManifestErrorCode.MANIFEST_ABSOLUTE_PATH,
                "Repository collector root cannot be a symbolic link.",
            )
        resolved = root.resolve(strict=True)
        if not resolved.is_dir():
            raise OSError
    except ManifestError:
        raise
    except OSError:
        raise ManifestError(
            ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
            "Repository collector root is unavailable.",
        ) from None
    reported = _run_git(resolved, ("rev-parse", "--show-toplevel")).strip()
    try:
        if Path(reported).resolve(strict=True) != resolved:
            _raise(
                ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
                "Repository collector root is not the Git root.",
            )
    except OSError:
        raise ManifestError(
            ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
            "Git root cannot be validated.",
        ) from None
    return resolved


def _run_git(root: Path, arguments: tuple[str, ...]) -> str:
    try:
        completed = subprocess.run(
            ("git", *arguments),
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=5,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise ManifestError(
            ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
            "Git metadata collector failed safely.",
        ) from None
    if completed.returncode != 0 or len(completed.stdout) > 10_000:
        _raise(
            ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
            "Git metadata collector returned an invalid result.",
        )
    return completed.stdout


def _coerce_model(
    model_type: type[ModelT],
    value: ModelT | Mapping[str, object],
    code: ManifestErrorCode,
) -> ModelT:
    try:
        native = (
            value.to_canonical_dict()  # type: ignore[attr-defined]
            if isinstance(value, model_type)
            else value
        )
        _validate_serialized_safety(native)
        return model_type.model_validate(native)  # type: ignore[attr-defined,no-any-return]
    except ManifestError:
        raise
    except (ValidationError, ValueError, TypeError):
        raise ManifestError(
            code, "Manifest section does not satisfy its canonical contract."
        ) from None


def _coerce_enum(
    enum_type: type[ModelT],
    value: ModelT | str,
    code: ManifestErrorCode,
) -> ModelT:
    try:
        return enum_type(value)  # type: ignore[call-arg]
    except (TypeError, ValueError):
        raise ManifestError(code, "Manifest enum value is unsupported.") from None


def _validate_run_id(run_id: str) -> None:
    if not isinstance(run_id, str) or _RUN_ID_PATTERN.fullmatch(run_id) is None:
        _raise(
            ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
            "Manifest run ID is malformed.",
        )


def _validate_timestamp(value: str) -> None:
    _parse_timestamp(value)


def _parse_timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        _raise(
            ManifestErrorCode.MANIFEST_TIMESTAMP_INVALID,
            "Manifest timestamp must be an RFC 3339 string.",
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ManifestError(
            ManifestErrorCode.MANIFEST_TIMESTAMP_INVALID,
            "Manifest timestamp must be an RFC 3339 string.",
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _raise(
            ManifestErrorCode.MANIFEST_TIMESTAMP_INVALID,
            "Manifest timestamp must include a timezone.",
        )
    return parsed


def _validate_artifact_id(value: str, code: ManifestErrorCode) -> None:
    if not isinstance(value, str) or _ARTIFACT_ID_PATTERN.fullmatch(value) is None:
        _raise(code, "Artifact identity is malformed.")
    if (
        _contains_secret(value)
        or _contains_direct_identifier(value)
        or _contains_absolute_path(value)
    ):
        _raise(
            ManifestErrorCode.MANIFEST_SECRET_CONTENT,
            "Artifact identity contains prohibited sensitive content.",
        )


def _validate_sha256(value: str, code: ManifestErrorCode) -> None:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        _raise(code, "SHA-256 metadata is malformed.")


def _safe_sha256_file(
    path: Path,
    code: ManifestErrorCode,
    *,
    require_single_link: bool = False,
) -> str:
    try:
        return sha256_file(path, require_single_link=require_single_link)
    except CanonicalJsonError:
        raise ManifestError(code, "Required file could not be hashed safely.") from None


def _validate_safe_short_string(
    value: str,
    *,
    maximum: int,
    code: ManifestErrorCode,
) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        _raise(code, "Manifest string metadata is invalid.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        _raise(
            ManifestErrorCode.MANIFEST_SECRET_CONTENT,
            "Manifest contains prohibited control characters.",
        )
    if _contains_absolute_path(value):
        _raise(ManifestErrorCode.MANIFEST_ABSOLUTE_PATH, "Manifest contains an absolute path.")
    if _contains_secret(value) or _contains_direct_identifier(value):
        _raise(ManifestErrorCode.MANIFEST_SECRET_CONTENT, "Manifest contains sensitive content.")
    return value


def _contains_unsafe_string(value: str) -> bool:
    return (
        any(ord(character) < 32 and character not in "\t\n\r" for character in value)
        or _contains_absolute_path(value)
        or _contains_secret(value)
        or _contains_direct_identifier(value)
    )


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


def _contains_secret(value: str) -> bool:
    return any(pattern.search(value) is not None for pattern in _SECRET_PATTERNS)


def _contains_direct_identifier(value: str) -> bool:
    return any(pattern.search(value) is not None for pattern in _DIRECT_IDENTIFIER_PATTERNS)


def _is_prohibited_metadata_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")
    return (
        normalized in _PROHIBITED_METADATA_KEYS
        or normalized.startswith(("raw_row_", "uploaded_row_", "direct_identifier_"))
        or normalized.endswith(
            (
                "_api_key",
                "_password",
                "_access_token",
                "_private_key",
                "_secret",
                "_prompt",
            )
        )
    )


def _raise(code: ManifestErrorCode, message: str) -> NoReturn:
    raise ManifestError(code, message)


__all__ = [
    "ArtifactVerificationResult",
    "CHECKSUM_INVENTORY_PATH",
    "ChecksumEntry",
    "ChecksumInventory",
    "ChecksumVerificationResult",
    "ManifestError",
    "ManifestErrorCode",
    "ManifestFinalizationResult",
    "ManifestVerificationResult",
    "RunManifestBuilder",
    "collect_code_provenance",
    "collect_environment_provenance",
    "complete_run",
    "create_run_manifest",
    "fail_run",
    "finalize_manifest",
    "manifest_sha256",
    "manifest_registries_from_snapshot",
    "parse_checksum_inventory",
    "register_artifact",
    "register_fallback",
    "register_gpt_call",
    "register_input",
    "registries_from_snapshot",
    "render_checksum_inventory",
    "start_run",
    "verify_checksum_inventory",
    "verify_manifest",
    "verify_registered_artifact",
    "verify_registered_artifacts",
    "write_checksum_inventory",
]
