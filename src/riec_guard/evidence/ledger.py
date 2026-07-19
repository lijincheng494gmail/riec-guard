from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

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
_MAX_EVIDENCE_ITEMS = 10_000


@dataclass(frozen=True, slots=True)
class LedgerVerificationResult:
    run_id: str
    item_count: int
    ledger_canonical_sha256: str
    graph: ProvenanceGraph


class EvidenceLedgerBuilder:
    """Run-scoped append-only builder that finalizes to one immutable verified ledger."""

    def __init__(self, run_id: str) -> None:
        _validate_run_id(run_id)
        self._run_id = run_id
        self._items: dict[str, EvidenceItem] = {}
        self._finalized: EvidenceLedger | None = None

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def finalized(self) -> bool:
        return self._finalized is not None

    @property
    def items(self) -> tuple[EvidenceItem, ...]:
        return tuple(self._items.values())

    def append(self, item: EvidenceItem) -> EvidenceItem:
        """Append verified evidence; identity-equal evidence reuses the first item."""

        if self._finalized is not None:
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_LEDGER_FINALIZED,
                "Evidence cannot be appended after ledger finalization.",
            )
        existing = self._items.get(item.evidence_id)
        if existing is not None:
            incoming_identity = evidence_identity(item)
            if incoming_identity.content_sha256 != existing.content_sha256:
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
        self._items[normalized.evidence_id] = normalized
        return normalized

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
    ) -> EvidenceItem:
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
        return self.append(item)

    def finalize(self) -> EvidenceLedger:
        if self._finalized is not None:
            verify_ledger(self._finalized, expected_run_id=self._run_id)
            return self._finalized
        if not self._items:
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_SCHEMA_INVALID,
                "Evidence ledger requires at least one item.",
            )
        validate_provenance_graph(tuple(self._items.values()))
        try:
            ledger = EvidenceLedger.model_validate(
                {
                    "schema_version": "1.0.0",
                    "run_id": self._run_id,
                    "canonicalization": _canonicalization_payload(),
                    "items": tuple(self._items.values()),
                }
            )
        except (ValidationError, ValueError, TypeError):
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_SCHEMA_INVALID,
                "Evidence ledger does not satisfy the canonical schema.",
            ) from None
        verify_ledger(ledger, expected_run_id=self._run_id)
        self._finalized = ledger
        return ledger


def append_evidence(builder: EvidenceLedgerBuilder, **fields: object) -> EvidenceItem:
    """Functional entry point for callers that prefer tool-style invocation."""

    return builder.append_new(**fields)  # type: ignore[arg-type]


def finalize_ledger(builder: EvidenceLedgerBuilder) -> EvidenceLedger:
    return builder.finalize()


def verify_ledger(
    ledger: EvidenceLedger | Mapping[str, object],
    *,
    expected_run_id: str | None = None,
) -> LedgerVerificationResult:
    """Revalidate schema, identities, source links, and insertion-order-independent DAG."""

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

    return LedgerVerificationResult(
        run_id=canonical.run_id,
        item_count=len(canonical.items),
        ledger_canonical_sha256=canonical_sha256(canonical_dict),
        graph=graph,
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
    "append_evidence",
    "finalize_ledger",
    "verify_ledger",
]
