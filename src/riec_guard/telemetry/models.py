from __future__ import annotations

from typing import Annotated, Literal, TypeAlias

from pydantic import Field, StringConstraints

from riec_guard.errors import (
    CanonicalModel,
    ImmutableTuple,
    JsonObject,
    LimitedString50,
    LimitedString100,
    LimitedString200,
    LimitedString300,
    LimitedString500,
    StrictStrEnum,
)

RunId: TypeAlias = Annotated[str, StringConstraints(pattern=r"^RUN-[A-F0-9]{12}$")]
ContractId: TypeAlias = Annotated[str, StringConstraints(pattern=r"^AC-[A-F0-9]{12}$")]
Sha256: TypeAlias = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
ArtifactId: TypeAlias = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")]
SemanticVersion: TypeAlias = Annotated[str, StringConstraints(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]


class RunMode(StrictStrEnum):
    PUBLIC_BUILTIN = "public_builtin"
    PUBLIC_UPLOAD = "public_upload"
    LOCAL_PRIVATE = "local_private"


class RunStatus(StrictStrEnum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    FAILED = "failed"


class InputClassification(StrictStrEnum):
    PUBLIC_SYNTHETIC = "public_synthetic"
    PUBLIC_UPLOAD = "public_upload"
    PRIVATE_INDUSTRIAL = "private_industrial"
    POLICY_TEXT = "policy_text"


class ContractConfirmationStatus(StrictStrEnum):
    DRAFT = "draft"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class GptPurpose(StrictStrEnum):
    CONTRACT_COMPILE = "contract_compile"
    MEMO_DRAFT = "memo_draft"
    CLAIM_AUDIT = "claim_audit"


class GptCallStatus(StrictStrEnum):
    NOT_CALLED = "not_called"
    SUCCESS = "success"
    FAILED = "failed"
    FALLBACK = "fallback"


class ManifestStorageRootClass(StrictStrEnum):
    PUBLIC_EPHEMERAL = "public_ephemeral"
    PRIVATE_LOCAL = "private_local"


class CodeProvenance(CanonicalModel):
    repository: LimitedString300
    commit_sha: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{7,40}$")]
    dirty: bool
    build_week_delta_version: LimitedString50


class EnvironmentProvenance(CanonicalModel):
    python: LimitedString50
    platform: LimitedString300
    dependency_lock_sha256: Sha256


class ManifestInput(CanonicalModel):
    artifact_id: ArtifactId
    sha256: Sha256
    classification: InputClassification
    row_count: Annotated[int, Field(ge=0)] | None


class ManifestContract(CanonicalModel):
    contract_id: ContractId
    sha256: Sha256
    schema_version: str
    confirmation_status: ContractConfirmationStatus


class ManifestCandidateRegistry(CanonicalModel):
    id: ArtifactId
    version: str
    sha256: Sha256


class ManifestRegistries(CanonicalModel):
    candidate_registry: ManifestCandidateRegistry
    protocol_versions: JsonObject
    action_engine_version: SemanticVersion


class ManifestRandomness(CanonicalModel):
    global_seed: int
    bootstrap_seed: int
    bootstrap_replicates: Annotated[int, Field(ge=0)]


class GptCallRecord(CanonicalModel):
    purpose: GptPurpose
    status: GptCallStatus
    request_id: LimitedString200 | None
    model: LimitedString100 | None
    latency_ms: Annotated[int, Field(ge=0)] | None
    input_tokens: Annotated[int, Field(ge=0)] | None
    output_tokens: Annotated[int, Field(ge=0)] | None
    fallback_used: bool
    error_class: LimitedString200 | None


class GptTelemetry(CanonicalModel):
    configured_model: LimitedString100
    api: Literal["responses"]
    store: Literal[False]
    calls: Annotated[ImmutableTuple[GptCallRecord], Field(max_length=20)]


class ManifestArtifact(CanonicalModel):
    artifact_id: ArtifactId
    path: LimitedString500
    sha256: Sha256
    media_type: LimitedString100
    public_safe: bool


class ManifestPrivacy(CanonicalModel):
    raw_rows_sent_to_gpt: Literal[False]
    direct_identifiers_sent_to_gpt: Literal[False]
    storage_root_class: ManifestStorageRootClass
    release_scan_passed: bool


class FallbackRecord(CanonicalModel):
    component: LimitedString100
    trigger: LimitedString500
    fallback: LimitedString500
    honesty_label: LimitedString500


class RunManifest(CanonicalModel):
    schema_logical_name = "run_manifest"

    schema_version: Literal["1.0.0"]
    run_id: RunId
    mode: RunMode
    started_at: str
    finished_at: str | None
    status: RunStatus
    code: CodeProvenance
    environment: EnvironmentProvenance
    inputs: Annotated[ImmutableTuple[ManifestInput], Field(min_length=1, max_length=20)]
    contract: ManifestContract
    registries: ManifestRegistries
    randomness: ManifestRandomness
    gpt: GptTelemetry
    artifacts: Annotated[ImmutableTuple[ManifestArtifact], Field(min_length=1, max_length=200)]
    privacy: ManifestPrivacy
    fallbacks: Annotated[ImmutableTuple[FallbackRecord], Field(max_length=50)]


__all__ = [
    "CodeProvenance",
    "EnvironmentProvenance",
    "FallbackRecord",
    "GptCallRecord",
    "GptTelemetry",
    "ManifestArtifact",
    "ManifestContract",
    "ManifestInput",
    "ManifestPrivacy",
    "ManifestRandomness",
    "ManifestRegistries",
    "RunManifest",
    "RunMode",
    "RunStatus",
]
