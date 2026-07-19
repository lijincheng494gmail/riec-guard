from __future__ import annotations

from typing import Annotated, Literal, TypeAlias

from pydantic import Field, StringConstraints, field_validator

from riec_guard.errors import (
    CanonicalModel,
    ImmutableTuple,
    JsonValue,
    LimitedString32,
    LimitedString100,
    LimitedString500,
    StrictStrEnum,
    UniqueTuple,
)

RunId: TypeAlias = Annotated[str, StringConstraints(pattern=r"^RUN-[A-F0-9]{12}$")]
EvidenceId: TypeAlias = Annotated[
    str, StringConstraints(pattern=r"^EV-[A-Z0-9_]{2,16}-[A-F0-9]{12}$")
]
Sha256: TypeAlias = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
ArtifactId: TypeAlias = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")]


class EvidenceComponent(StrictStrEnum):
    CONTRACT = "CONTRACT"
    PROFILE = "PROFILE"
    RIEC = "RIEC"
    PROTOCOL = "PROTOCOL"
    BOOTSTRAP = "BOOTSTRAP"
    STABILITY = "STABILITY"
    ACTION = "ACTION"
    BOUNDARY = "BOUNDARY"
    CLAIM = "CLAIM"
    SYSTEM = "SYSTEM"


class EvidenceKind(StrictStrEnum):
    STATISTIC = "statistic"
    DIAGNOSTIC = "diagnostic"
    WARNING = "warning"
    FAILURE = "failure"
    BOUNDARY = "boundary"
    DECISION_REASON = "decision_reason"
    PROVENANCE = "provenance"
    CLAIM_RULE = "claim_rule"


class EvidenceStatus(StrictStrEnum):
    OK = "ok"
    WARNING = "warning"
    MATERIAL = "material"
    BLOCKING = "blocking"
    NOT_APPLICABLE = "not_applicable"


class EvidenceCanonicalization(CanonicalModel):
    json_encoding: Literal["utf-8"]
    sort_keys: Literal[True]
    excluded_fields: ImmutableTuple[str]
    hash_algorithm: Literal["sha256"]
    id_format: Literal["EV-<COMPONENT>-<FIRST12_UPPER_HEX>"]

    @field_validator("excluded_fields")
    @classmethod
    def _fixed_excluded_fields(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != ("evidence_id", "created_at", "content_sha256"):
            raise ValueError("canonical excluded fields are fixed")
        return value


class EvidenceSourceRef(CanonicalModel):
    artifact_id: ArtifactId
    artifact_sha256: Sha256
    locator: LimitedString500 | None


class EvidenceItem(CanonicalModel):
    evidence_id: EvidenceId
    content_sha256: Sha256
    component: EvidenceComponent
    kind: EvidenceKind
    status: EvidenceStatus
    statement: Annotated[str, StringConstraints(min_length=1, max_length=3000)]
    value: JsonValue
    unit: LimitedString32 | None
    source_refs: Annotated[ImmutableTuple[EvidenceSourceRef], Field(max_length=20)]
    parent_evidence_ids: Annotated[UniqueTuple[EvidenceId], Field(max_length=100)]
    input_sha256: Sha256
    contract_sha256: Sha256
    implementation_version: LimitedString100
    created_at: str


class EvidenceLedger(CanonicalModel):
    schema_logical_name = "evidence_ledger"

    schema_version: Literal["1.0.0"]
    run_id: RunId
    canonicalization: EvidenceCanonicalization
    items: Annotated[ImmutableTuple[EvidenceItem], Field(min_length=1, max_length=10_000)]


__all__ = [
    "EvidenceCanonicalization",
    "EvidenceComponent",
    "EvidenceItem",
    "EvidenceKind",
    "EvidenceLedger",
    "EvidenceSourceRef",
    "EvidenceStatus",
]
