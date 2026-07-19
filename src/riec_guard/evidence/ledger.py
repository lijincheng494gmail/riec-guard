from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from pydantic import ValidationError

from riec_guard.evidence.ids import (
    EvidenceError,
    EvidenceErrorCode,
    canonical_sha256,
    create_evidence_item,
    evidence_identity,
    verify_evidence_item,
)
from riec_guard.evidence.models import (
    EvidenceCanonicalization,
    EvidenceComponent,
    EvidenceItem,
    EvidenceKind,
    EvidenceLedger,
    EvidenceSourceRef,
    EvidenceStatus,
)
from riec_guard.evidence.provenance import ProvenanceGraph, validate_provenance_graph

_RUN_ID_PATTERN = re.compile(r"RUN-[A-F0-9]{12}\Z")
_SHA256_PATTERN = re.compile(r"[a-f0-9]{64}\Z")
_MAX_EVIDENCE_ITEMS = 10_000
_RUN_BOUND_AUTHORITY_KEY = secrets.token_bytes(32)


@dataclass(frozen=True, slots=True, init=False)
class RunBoundEvidence:
    """Immutable runtime ownership record minted only from a builder or canonical ledger."""

    run_id: str
    item: EvidenceItem
    _ownership_witness: str = field(init=False, repr=False, compare=False)

    def __init__(
        self,
        run_id: str,
        item: EvidenceItem,
    ) -> None:
        raise EvidenceError(
            EvidenceErrorCode.EVIDENCE_RUN_MISMATCH,
            "Evidence ownership records require a trusted binding path.",
        )


@dataclass(frozen=True, slots=True)
class LedgerVerificationResult:
    run_id: str
    item_count: int
    ledger_canonical_sha256: str
    graph: ProvenanceGraph
    run_ownership_verified: bool


class EvidenceLedgerBuilder:
    """Run-scoped append-only builder that finalizes to one immutable verified ledger."""

    def __init__(self, run_id: str) -> None:
        _validate_run_id(run_id)
        self._run_id = run_id
        self._items: dict[str, RunBoundEvidence] = {}
        self._finalized: EvidenceLedger | None = None

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def finalized(self) -> bool:
        return self._finalized is not None

    @property
    def items(self) -> tuple[EvidenceItem, ...]:
        return tuple(record.item for record in self._items.values())

    @property
    def bound_items(self) -> tuple[RunBoundEvidence, ...]:
        return tuple(self._items.values())

    def append(self, evidence: RunBoundEvidence | EvidenceItem) -> RunBoundEvidence:
        """Append trusted same-run evidence; naked imported items fail closed."""

        if self._finalized is not None:
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_LEDGER_FINALIZED,
                "Evidence cannot be appended after ledger finalization.",
            )
        if not isinstance(evidence, RunBoundEvidence) or not _is_authentic_run_bound(evidence):
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_RUN_MISMATCH,
                "Evidence ownership context is required for imported evidence.",
            )
        _validate_run_id(evidence.run_id)
        if evidence.run_id != self._run_id:
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_RUN_MISMATCH,
                "Evidence does not belong to the target run.",
            )
        item = evidence.item
        if not isinstance(item, EvidenceItem):
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_SCHEMA_INVALID,
                "Run-bound evidence does not contain a canonical item.",
            )
        existing = self._items.get(item.evidence_id)
        if existing is not None:
            incoming_identity = evidence_identity(item)
            if incoming_identity.content_sha256 != existing.item.content_sha256:
                raise EvidenceError(
                    EvidenceErrorCode.EVIDENCE_COLLISION,
                    "Evidence ID is associated with different canonical content.",
                )
            verify_evidence_item(item)
            return existing
        if len(self._items) >= _MAX_EVIDENCE_ITEMS:
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_SCHEMA_INVALID,
                "Evidence ledger exceeds the canonical item limit.",
            )
        verify_evidence_item(item)
        try:
            normalized = EvidenceItem.model_validate(item.to_canonical_dict())
        except (ValidationError, ValueError, TypeError):
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_SCHEMA_INVALID,
                "Evidence item cannot be normalized safely.",
            ) from None
        verify_evidence_item(normalized)
        bound = _mint_run_bound(self._run_id, normalized)
        self._items[normalized.evidence_id] = bound
        return bound

    def append_new(
        self,
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
    ) -> RunBoundEvidence:
        item = create_evidence_item(
            component=component,
            kind=kind,
            status=status,
            statement=statement,
            value=value,
            unit=unit,
            source_refs=source_refs,
            parent_evidence_ids=parent_evidence_ids,
            input_sha256=input_sha256,
            contract_sha256=contract_sha256,
            implementation_version=implementation_version,
            created_at=created_at,
        )
        return self.append(_mint_run_bound(self._run_id, item))

    def finalize(self) -> EvidenceLedger:
        if self._finalized is not None:
            verify_ledger(
                self._finalized,
                expected_run_id=self._run_id,
                bound_items=self.bound_items,
            )
            return self._finalized
        if not self._items:
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_SCHEMA_INVALID,
                "Evidence ledger requires at least one item.",
            )
        canonical_items = self.items
        _validate_bound_items(self.bound_items, expected_run_id=self._run_id)
        validate_provenance_graph(canonical_items)
        try:
            ledger = EvidenceLedger.model_validate(
                {
                    "schema_version": "1.0.0",
                    "run_id": self._run_id,
                    "canonicalization": _canonicalization_payload(),
                    "items": canonical_items,
                }
            )
        except (ValidationError, ValueError, TypeError):
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_SCHEMA_INVALID,
                "Evidence ledger does not satisfy the canonical schema.",
            ) from None
        verify_ledger(
            ledger,
            expected_run_id=self._run_id,
            bound_items=self.bound_items,
        )
        self._finalized = ledger
        return ledger


def append_evidence(builder: EvidenceLedgerBuilder, **fields: object) -> RunBoundEvidence:
    """Functional entry point for callers that prefer tool-style invocation."""

    return builder.append_new(**fields)  # type: ignore[arg-type]


def finalize_ledger(builder: EvidenceLedgerBuilder) -> EvidenceLedger:
    return builder.finalize()


def bind_ledger_items(
    ledger: EvidenceLedger,
    *,
    expected_source_run_id: str | None = None,
    expected_ledger_sha256: str | None = None,
) -> tuple[RunBoundEvidence, ...]:
    """Bind imported items using trusted source-run and canonical-ledger expectations."""

    if not isinstance(ledger, EvidenceLedger):
        raise EvidenceError(
            EvidenceErrorCode.EVIDENCE_RUN_MISMATCH,
            "Evidence ownership binding requires a canonical source ledger.",
        )
    if (
        not isinstance(expected_source_run_id, str)
        or _RUN_ID_PATTERN.fullmatch(expected_source_run_id) is None
        or not isinstance(expected_ledger_sha256, str)
        or _SHA256_PATTERN.fullmatch(expected_ledger_sha256) is None
    ):
        raise EvidenceError(
            EvidenceErrorCode.EVIDENCE_RUN_MISMATCH,
            "Evidence import requires trusted source-ledger ownership context.",
        )
    verification = verify_ledger(ledger)
    if ledger.run_id != expected_source_run_id or not hmac.compare_digest(
        verification.ledger_canonical_sha256,
        expected_ledger_sha256,
    ):
        raise EvidenceError(
            EvidenceErrorCode.EVIDENCE_RUN_MISMATCH,
            "Evidence source ledger does not match the trusted ownership context.",
        )
    return tuple(_mint_run_bound(ledger.run_id, item) for item in ledger.items)


def verify_ledger(
    ledger: EvidenceLedger | Mapping[str, object],
    *,
    expected_run_id: str | None = None,
    bound_items: Sequence[RunBoundEvidence] | None = None,
) -> LedgerVerificationResult:
    """Verify canonical structure and, when supplied, distinct runtime run ownership."""

    try:
        canonical = (
            ledger if isinstance(ledger, EvidenceLedger) else EvidenceLedger.model_validate(ledger)
        )
        canonical_dict = canonical.to_canonical_dict()
    except (ValidationError, ValueError, TypeError):
        raise EvidenceError(
            EvidenceErrorCode.EVIDENCE_SCHEMA_INVALID,
            "Evidence ledger does not satisfy the canonical schema.",
        ) from None

    _validate_run_id(canonical.run_id)
    if expected_run_id is not None:
        _validate_run_id(expected_run_id)
        if canonical.run_id != expected_run_id:
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_RUN_MISMATCH,
                "Evidence ledger does not belong to the expected run.",
            )
        if bound_items is None:
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_RUN_MISMATCH,
                "Expected-run verification requires trusted evidence ownership context.",
            )
    _validate_canonicalization(canonical.canonicalization)

    graph = validate_provenance_graph(canonical.items)
    seen: set[str] = set()
    full_hashes: dict[str, str] = {}
    for item in sorted(canonical.items, key=lambda evidence: evidence.evidence_id):
        if item.evidence_id in seen:
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_DUPLICATE_ID,
                "Evidence ledger contains a duplicate evidence ID.",
            )
        identity = verify_evidence_item(item)
        previous_id = full_hashes.get(identity.content_sha256)
        if previous_id is not None and previous_id != identity.evidence_id:
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_COLLISION,
                "Canonical evidence content is associated with inconsistent identities.",
            )
        seen.add(item.evidence_id)
        full_hashes[identity.content_sha256] = identity.evidence_id

    ownership_verified = False
    if bound_items is not None:
        ownership_records = tuple(bound_items)
        _validate_bound_items(ownership_records, expected_run_id=canonical.run_id)
        bound_canonical = tuple(record.item.to_canonical_dict() for record in ownership_records)
        ledger_canonical = tuple(item.to_canonical_dict() for item in canonical.items)
        if bound_canonical != ledger_canonical:
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_RUN_MISMATCH,
                "Evidence ownership context does not match the canonical ledger.",
            )
        ownership_verified = True

    return LedgerVerificationResult(
        run_id=canonical.run_id,
        item_count=len(canonical.items),
        ledger_canonical_sha256=canonical_sha256(canonical_dict),
        graph=graph,
        run_ownership_verified=ownership_verified,
    )


def _mint_run_bound(run_id: str, item: EvidenceItem) -> RunBoundEvidence:
    _validate_run_id(run_id)
    if not isinstance(item, EvidenceItem):
        raise EvidenceError(
            EvidenceErrorCode.EVIDENCE_SCHEMA_INVALID,
            "Evidence ownership binding requires a canonical item.",
        )
    record = object.__new__(RunBoundEvidence)
    object.__setattr__(record, "run_id", run_id)
    object.__setattr__(record, "item", item)
    object.__setattr__(record, "_ownership_witness", _run_bound_witness(run_id, item))
    return record


def _run_bound_witness(run_id: str, item: EvidenceItem) -> str:
    item_sha256 = canonical_sha256(item.to_canonical_dict())
    payload = f"{run_id}\x1f{item_sha256}".encode("utf-8")
    return hmac.new(_RUN_BOUND_AUTHORITY_KEY, payload, hashlib.sha256).hexdigest()


def _is_authentic_run_bound(record: object) -> bool:
    if not isinstance(record, RunBoundEvidence) or type(record) is not RunBoundEvidence:
        return False
    try:
        if (
            not isinstance(record.run_id, str)
            or not isinstance(record.item, EvidenceItem)
            or not isinstance(record._ownership_witness, str)
            or _SHA256_PATTERN.fullmatch(record._ownership_witness) is None
        ):
            return False
        expected = _run_bound_witness(record.run_id, record.item)
    except (AttributeError, TypeError, ValueError):
        return False
    return hmac.compare_digest(record._ownership_witness, expected)


def _validate_bound_items(
    bound_items: Sequence[RunBoundEvidence],
    *,
    expected_run_id: str,
) -> None:
    _validate_run_id(expected_run_id)
    if not isinstance(bound_items, (tuple, list)):
        raise EvidenceError(
            EvidenceErrorCode.EVIDENCE_RUN_MISMATCH,
            "Evidence ownership context is invalid.",
        )
    for record in bound_items:
        if (
            not _is_authentic_run_bound(record)
            or record.run_id != expected_run_id
            or not isinstance(record.item, EvidenceItem)
        ):
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_RUN_MISMATCH,
                "Evidence ownership context does not match the target run.",
            )


def _canonicalization_payload() -> dict[str, object]:
    return {
        "json_encoding": "utf-8",
        "sort_keys": True,
        "excluded_fields": ["evidence_id", "created_at", "content_sha256"],
        "hash_algorithm": "sha256",
        "id_format": "EV-<COMPONENT>-<FIRST12_UPPER_HEX>",
    }


def _validate_canonicalization(value: EvidenceCanonicalization) -> None:
    if value.to_canonical_dict() != _canonicalization_payload():
        raise EvidenceError(
            EvidenceErrorCode.EVIDENCE_SCHEMA_INVALID,
            "Evidence canonicalization metadata does not match the frozen algorithm.",
        )


def _validate_run_id(run_id: str) -> None:
    if not isinstance(run_id, str) or _RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise EvidenceError(
            EvidenceErrorCode.EVIDENCE_RUN_MISMATCH,
            "Evidence run ID is malformed.",
        )


__all__ = [
    "EvidenceLedgerBuilder",
    "LedgerVerificationResult",
    "RunBoundEvidence",
    "append_evidence",
    "bind_ledger_items",
    "finalize_ledger",
    "verify_ledger",
]
