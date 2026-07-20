from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from typing import TypedDict
from weakref import WeakKeyDictionary

from riec_guard.contract.models import (
    AuditContract,
    CandidateRegistry,
    DatasetProfile,
    RiecSelection,
)
from riec_guard.contract.validator import analysis_is_permitted, validate_audit_contract
from riec_guard.domain.source import SourceRepository
from riec_guard.errors import (
    ApplicationError,
    CanonicalModel,
    ErrorClass,
    ErrorEnvelope,
    ErrorStage,
)
from riec_guard.evidence.ids import EvidenceError, canonical_sha256, create_evidence_item
from riec_guard.evidence.ledger import EvidenceLedgerBuilder
from riec_guard.evidence.models import (
    EvidenceComponent,
    EvidenceItem,
    EvidenceKind,
    EvidenceSourceRef,
    EvidenceStatus,
)
from riec_guard.riec.design import DesignFailure, RiecReasonCode, prepare_dataset
from riec_guard.riec.grouped_cv import (
    CandidateEvaluation,
    EvaluationStatus,
    evaluate_grouped_candidates,
)
from riec_guard.riec.registry import (
    FROZEN_BASELINE_CANDIDATE_ID,
    FROZEN_CANDIDATE_IDS,
    ConfigSnapshot,
    RegistryConfigType,
    RunRegistrySnapshot,
    load_run_registry_snapshot,
)
from riec_guard.riec.selection import (
    RiecDecision,
    SelectionFailure,
    build_canonical_selection,
    compute_riec_decision,
)

_SOURCE_RUN_ID = re.compile(r"RUN-[a-f0-9]{32}\Z")
_IMPLEMENTATION_VERSION = "riec-core.1.0.0"
_RUN_BRIDGE_LOCK = threading.RLock()
_RUN_BRIDGES: WeakKeyDictionary[SourceRepository, dict[str, str]] = WeakKeyDictionary()


class _EvidenceFields(TypedDict):
    component: EvidenceComponent
    kind: EvidenceKind
    status: EvidenceStatus
    statement: str
    value: object
    unit: str | None
    source_refs: tuple[EvidenceSourceRef, ...]
    parent_evidence_ids: tuple[str, ...]
    input_sha256: str
    contract_sha256: str
    implementation_version: str
    created_at: str


@dataclass(frozen=True, slots=True)
class RiecCoreResult:
    """Immutable aggregate result; it deliberately contains no source rows."""

    selection: RiecSelection
    evidence_item: EvidenceItem
    decision: RiecDecision
    candidate_evaluations: tuple[CandidateEvaluation, ...]
    source_run_id: str
    artifact_run_id: str
    dataset_id: str
    dataset_sha256: str
    contract_id: str
    contract_sha256: str
    candidate_registry_id: str
    candidate_registry_version: str
    candidate_registry_sha256: str
    splitter: str
    risk_aggregation: str


def run_grouped_riec_core(
    repository: SourceRepository,
    *,
    run_id: str,
    source_id: str,
    contract: AuditContract,
    dataset_profile: DatasetProfile,
    registry_snapshot: RunRegistrySnapshot,
    evidence_builder: EvidenceLedgerBuilder | None = None,
) -> RiecCoreResult | ErrorEnvelope:
    """Run the frozen grouped RIEC core through the source/run ownership boundary.

    Source storage uses ``RUN-`` plus 32 lowercase hex characters while canonical
    artifacts use ``RUN-`` plus 12 uppercase hex characters. The accepted bridge is
    explicit and deterministic: the first 12 source-run hex characters, uppercased.
    A supplied evidence builder must already belong to that derived artifact run.
    """

    try:
        if (
            not isinstance(repository, SourceRepository)
            or not isinstance(contract, AuditContract)
            or not isinstance(dataset_profile, DatasetProfile)
            or not isinstance(registry_snapshot, RunRegistrySnapshot)
            or evidence_builder is not None
            and not isinstance(evidence_builder, EvidenceLedgerBuilder)
        ):
            return _error(
                RiecReasonCode.RIEC_SELECTION_UNAVAILABLE,
                ErrorClass.VALIDATION,
                "The grouped RIEC service received an invalid typed input.",
                recoverable=False,
                user_action="Use the canonical run, contract, profile, registry, and evidence types.",
            )
        artifact_run_id = _artifact_run_id(run_id)
        if evidence_builder is not None and evidence_builder.run_id != artifact_run_id:
            return _error(
                RiecReasonCode.RIEC_RUN_OWNERSHIP_MISMATCH,
                ErrorClass.SECURITY_BLOCK,
                "The evidence builder does not belong to the supplied source run.",
                recoverable=False,
                user_action="Use the run-owned evidence builder for this analysis.",
            )
        registry = _trusted_candidate_registry(registry_snapshot, contract)
        try:
            source = repository.get_source(run_id, source_id)
            normalized = repository.read_normalized_bytes(run_id, source_id)
        except ApplicationError:
            return _error(
                RiecReasonCode.RIEC_SOURCE_NOT_FOUND,
                ErrorClass.VALIDATION,
                "The requested normalized source is unavailable for this run.",
                recoverable=True,
                user_action="Select a normalized source owned by the current run.",
            )
        _bind_source_artifact_run(repository, run_id, artifact_run_id)
        dataset_sha256 = hashlib.sha256(normalized).hexdigest()
        if (
            source.run_id != run_id
            or source.normalized_sha256 is None
            or source.normalized_sha256 != dataset_sha256
            or dataset_profile.dataset_sha256 != dataset_sha256
            or contract.source.dataset_sha256 != dataset_sha256
        ):
            return _error(
                RiecReasonCode.RIEC_DATASET_MISMATCH,
                ErrorClass.SECURITY_BLOCK,
                "Normalized source identity does not match the confirmed analysis inputs.",
                recoverable=False,
                user_action="Re-profile the run-owned normalized source and confirm a new contract.",
            )

        validation = validate_audit_contract(contract, dataset_profile)
        if not analysis_is_permitted(validation) or validation.canonical_contract_sha256 is None:
            return _error(
                RiecReasonCode.RIEC_CONTRACT_NOT_PERMITTED,
                ErrorClass.VALIDATION,
                "The confirmed audit contract does not permit analysis.",
                recoverable=True,
                user_action="Resolve blocking contract issues and confirm the contract again.",
            )
        prepared = prepare_dataset(normalized, contract)
        if prepared.n_groups < contract.evidence_profile.min_groups_exploratory:
            raise DesignFailure(
                RiecReasonCode.RIEC_INSUFFICIENT_GROUPS,
                "Deployment-group support is below the confirmed exploratory minimum.",
            )
        evaluations = evaluate_grouped_candidates(
            prepared,
            tuple(registry.payload.candidates),
            max_exact_logo_groups=contract.riec.max_exact_logo_groups,
        )
        decision = compute_riec_decision(
            evaluations,
            c=float(contract.riec.c),
            near_tie_abs_tol=float(contract.riec.near_tie_abs_tol),
            near_tie_rel_tol=float(contract.riec.near_tie_rel_tol),
        )
        evidence_fields = _evidence_fields(
            decision=decision,
            evaluations=evaluations,
            dataset_profile=dataset_profile,
            contract=contract,
            contract_sha256=validation.canonical_contract_sha256,
            registry_snapshot=registry_snapshot,
            evidence_builder=evidence_builder,
        )
        evidence_item = create_evidence_item(**evidence_fields)
        selection = build_canonical_selection(
            decision,
            run_id=artifact_run_id,
            registry_id=registry.logical_id,
            c=float(contract.riec.c),
            evidence_id=evidence_item.evidence_id,
        )
        if evidence_builder is not None:
            try:
                appended = evidence_builder.append_new(**evidence_fields)
            except EvidenceError:
                return _error(
                    RiecReasonCode.RIEC_EVIDENCE_APPEND_FAILED,
                    ErrorClass.SECURITY_BLOCK,
                    "The aggregate RIEC evidence item could not be bound to this run.",
                    recoverable=False,
                    user_action="Use an active evidence builder owned by this run.",
                )
            if appended.item.evidence_id != evidence_item.evidence_id:
                return _error(
                    RiecReasonCode.RIEC_EVIDENCE_APPEND_FAILED,
                    ErrorClass.SECURITY_BLOCK,
                    "The aggregate RIEC evidence identity changed during run binding.",
                    recoverable=False,
                    user_action="Stop this run and preserve the safe error artifact for review.",
                )
            evidence_item = appended.item

        return RiecCoreResult(
            selection=selection,
            evidence_item=evidence_item,
            decision=decision,
            candidate_evaluations=evaluations,
            source_run_id=run_id,
            artifact_run_id=artifact_run_id,
            dataset_id=dataset_profile.dataset_id,
            dataset_sha256=dataset_sha256,
            contract_id=contract.contract_id,
            contract_sha256=validation.canonical_contract_sha256,
            candidate_registry_id=registry.logical_id,
            candidate_registry_version=registry.version,
            candidate_registry_sha256=registry.canonical_json_sha256,
            splitter="leave_one_deployment_group_out",
            risk_aggregation="row_weighted_grouped_mse",
        )
    except DesignFailure as error:
        return _design_error(error)
    except SelectionFailure as error:
        return _selection_error(error)
    except (EvidenceError, ArithmeticError, AttributeError, TypeError, ValueError):
        return _error(
            RiecReasonCode.RIEC_SELECTION_UNAVAILABLE,
            ErrorClass.INTERNAL,
            "The grouped RIEC result could not be constructed safely.",
            recoverable=False,
            user_action="Retry once; if the problem persists, preserve the safe error artifact.",
        )


def _artifact_run_id(source_run_id: str) -> str:
    if _SOURCE_RUN_ID.fullmatch(source_run_id) is None:
        raise DesignFailure(
            RiecReasonCode.RIEC_SOURCE_NOT_FOUND,
            "The source run identifier is invalid.",
        )
    return f"RUN-{source_run_id[4:16].upper()}"


def _bind_source_artifact_run(
    repository: SourceRepository,
    source_run_id: str,
    artifact_run_id: str,
) -> None:
    """Reject a canonical-ID collision within one source repository authority."""

    with _RUN_BRIDGE_LOCK:
        bindings = _RUN_BRIDGES.setdefault(repository, {})
        existing = bindings.get(artifact_run_id)
        if existing is not None and existing != source_run_id:
            raise DesignFailure(
                RiecReasonCode.RIEC_RUN_OWNERSHIP_MISMATCH,
                "The canonical run bridge collides with another source run.",
            )
        bindings[artifact_run_id] = source_run_id


def _trusted_candidate_registry(
    registry_snapshot: RunRegistrySnapshot, contract: AuditContract
) -> ConfigSnapshot[CandidateRegistry]:
    trusted = load_run_registry_snapshot()
    supplied_snapshots: tuple[ConfigSnapshot[CanonicalModel], ...] = (
        registry_snapshot.candidate_registry,
        registry_snapshot.protocol_registry,
        registry_snapshot.evidence_profile,
        registry_snapshot.policy_registry,
        registry_snapshot.claim_ruleset,
    )
    trusted_snapshots: tuple[ConfigSnapshot[CanonicalModel], ...] = (
        trusted.candidate_registry,
        trusted.protocol_registry,
        trusted.evidence_profile,
        trusted.policy_registry,
        trusted.claim_ruleset,
    )
    snapshots_match = all(
        isinstance(supplied, ConfigSnapshot)
        and supplied.logical_id == expected.logical_id
        and supplied.config_type is expected.config_type
        and supplied.version == expected.version
        and supplied.repository_relative_source == expected.repository_relative_source
        and supplied.file_sha256 == expected.file_sha256
        and supplied.canonical_json_sha256 == expected.canonical_json_sha256
        and supplied.canonical_json_sha256 == canonical_sha256(supplied.payload.to_canonical_dict())
        and supplied.frozen is True
        and supplied.frozen is expected.frozen
        and supplied.payload.to_canonical_dict() == expected.payload.to_canonical_dict()
        for supplied, expected in zip(supplied_snapshots, trusted_snapshots, strict=True)
    )
    if not snapshots_match:
        raise DesignFailure(
            RiecReasonCode.RIEC_REGISTRY_MISMATCH,
            "The supplied run registry does not match the trusted frozen snapshot.",
        )
    combined_payload = {
        "configs": [
            {
                "logical_id": snapshot.logical_id,
                "config_type": snapshot.config_type.value,
                "version": snapshot.version,
                "canonical_json_sha256": snapshot.canonical_json_sha256,
            }
            for snapshot in supplied_snapshots
        ]
    }
    supplied = registry_snapshot.candidate_registry
    identities_match = (
        snapshots_match
        and registry_snapshot.combined_canonical_sha256 == canonical_sha256(combined_payload)
        and registry_snapshot.combined_canonical_sha256 == trusted.combined_canonical_sha256
        and supplied.logical_id == contract.riec.candidate_registry_id
        and supplied.config_type is RegistryConfigType.CANDIDATE_REGISTRY
        and supplied.payload.registry_id == supplied.logical_id
        and supplied.payload.registry_version == supplied.version
        and supplied.payload.baseline_candidate_id == FROZEN_BASELINE_CANDIDATE_ID
        and tuple(item.candidate_id for item in supplied.payload.candidates) == FROZEN_CANDIDATE_IDS
        and all(item.enabled for item in supplied.payload.candidates)
    )
    if not identities_match:
        raise DesignFailure(
            RiecReasonCode.RIEC_REGISTRY_MISMATCH,
            "The supplied run registry does not match the trusted frozen snapshot.",
        )
    return supplied


def _evidence_fields(
    *,
    decision: RiecDecision,
    evaluations: tuple[CandidateEvaluation, ...],
    dataset_profile: DatasetProfile,
    contract: AuditContract,
    contract_sha256: str,
    registry_snapshot: RunRegistrySnapshot,
    evidence_builder: EvidenceLedgerBuilder | None,
) -> _EvidenceFields:
    parent_ids: tuple[str, ...] = ()
    if evidence_builder is not None:
        parent_ids = tuple(
            sorted(
                item.evidence_id
                for item in evidence_builder.items
                if item.component is EvidenceComponent.CONTRACT
                and item.input_sha256 == dataset_profile.dataset_sha256
                and item.contract_sha256 == contract_sha256
            )
        )
    counts = {
        "eligible": sum(item.score is not None for item in decision.candidates),
        "ineligible": sum(
            item.evaluation.status is EvaluationStatus.INELIGIBLE
            or item.evaluation.status is EvaluationStatus.OK
            and item.score is None
            for item in decision.candidates
        ),
        "failed": sum(
            item.status in {EvaluationStatus.FIT_FAILED, EvaluationStatus.PREDICTION_FAILED}
            for item in evaluations
        ),
    }
    candidate_table = [
        {
            "candidate_id": item.evaluation.candidate_id,
            "status": (
                item.evaluation.status.value
                if item.score is not None or item.evaluation.status is not EvaluationStatus.OK
                else "score_unavailable"
            ),
            "realized_rank": (
                item.evaluation.full_fit.realized_rank
                if item.evaluation.full_fit is not None
                else None
            ),
            "bic_eff": (
                item.evaluation.full_fit.bic_eff if item.evaluation.full_fit is not None else None
            ),
            "grouped_risk": item.evaluation.grouped_risk,
            "group_balanced_risk": item.evaluation.group_balanced_risk,
            "xpe": item.score.xpe if item.score is not None else None,
            "c_score": item.score.c_score if item.score is not None else None,
            "failure_code": item.score_failure_code or item.evaluation.failure_code,
        }
        for item in decision.candidates
    ]
    boundary = decision.switching_boundary
    value: dict[str, object] = {
        "candidate_registry_id": registry_snapshot.candidate_registry.logical_id,
        "candidate_registry_version": registry_snapshot.candidate_registry.version,
        "split_rule": "leave_one_deployment_group_out",
        "risk_aggregation": "row_weighted_grouped_mse",
        "c": float(contract.riec.c),
        "candidate_counts": counts,
        "candidate_table": candidate_table,
        "provenance_mode": "contract_parent_bound" if parent_ids else "standalone_aggregate",
        "raw_numeric_winner": decision.raw_numeric_winner,
        "winner": decision.winner,
        "runner_up": decision.runner_up,
        "score_gap": decision.score_gap,
        "near_tie": decision.near_tie,
        "equivalence_set": list(decision.equivalence_set),
        "switching_boundary": {
            "status": boundary.status.value,
            "boundary_c": boundary.switch_c,
            "preferred_below": boundary.preference_below,
            "preferred_above": boundary.preference_above,
            "current_c": boundary.current_c,
            "preferred_at_current": boundary.preference_at_current,
        },
        "implementation_version": _IMPLEMENTATION_VERSION,
    }
    created_at = contract.confirmation.confirmed_at or contract.created_at
    if created_at is None:
        raise DesignFailure(
            RiecReasonCode.RIEC_CONTRACT_NOT_PERMITTED,
            "A confirmed contract timestamp is required for evidence.",
        )
    return {
        "component": EvidenceComponent.RIEC,
        "kind": EvidenceKind.STATISTIC,
        "status": EvidenceStatus.WARNING if decision.near_tie else EvidenceStatus.OK,
        "statement": "Grouped RIEC-L1 evaluated the frozen structural candidate library.",
        "value": value,
        "unit": None,
        "source_refs": (
            EvidenceSourceRef.model_validate(
                {
                    "artifact_id": "normalized.dataset",
                    "artifact_sha256": dataset_profile.dataset_sha256,
                    "locator": "run-owned-normalized-csv",
                }
            ),
            EvidenceSourceRef.model_validate(
                {
                    "artifact_id": "candidate.registry",
                    "artifact_sha256": registry_snapshot.candidate_registry.canonical_json_sha256,
                    "locator": registry_snapshot.candidate_registry.logical_id,
                }
            ),
        ),
        "parent_evidence_ids": parent_ids,
        "input_sha256": dataset_profile.dataset_sha256,
        "contract_sha256": contract_sha256,
        "implementation_version": _IMPLEMENTATION_VERSION,
        "created_at": created_at,
    }


def _design_error(error: DesignFailure) -> ErrorEnvelope:
    if error.code is RiecReasonCode.RIEC_TOO_MANY_GROUPS_EXACT_LOGO:
        error_class = ErrorClass.SCALE_LIMIT
    elif error.code in {
        RiecReasonCode.RIEC_REGISTRY_MISMATCH,
        RiecReasonCode.RIEC_RUN_OWNERSHIP_MISMATCH,
    }:
        error_class = ErrorClass.SECURITY_BLOCK
    elif error.code in {
        RiecReasonCode.RIEC_INVALID_QUANTITY,
        RiecReasonCode.RIEC_INVALID_DEPLOYMENT_GROUP,
        RiecReasonCode.RIEC_INSUFFICIENT_GROUPS,
        RiecReasonCode.RIEC_DATASET_MISMATCH,
    }:
        error_class = ErrorClass.DATA_QUALITY
    else:
        error_class = ErrorClass.VALIDATION
    return _error(
        error.code,
        error_class,
        "The grouped RIEC input failed a deterministic safety or feasibility check.",
        recoverable=True,
        user_action="Correct or reconfirm the public dataset inputs before retrying.",
    )


def _selection_error(error: SelectionFailure) -> ErrorEnvelope:
    return _error(
        error.code,
        ErrorClass.FIT_FAILURE,
        "The frozen grouped RIEC selection could not be completed.",
        recoverable=True,
        user_action="Review aggregate candidate feasibility and confirm a valid baseline dataset.",
    )


def _error(
    code: RiecReasonCode,
    error_class: ErrorClass,
    message: str,
    *,
    recoverable: bool,
    user_action: str,
) -> ErrorEnvelope:
    identity = json.dumps(
        {"code": code.value, "error_class": error_class.value},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return ErrorEnvelope.model_validate(
        {
            "schema_version": "1.0.0",
            "error_id": f"ERR-{hashlib.sha256(identity).hexdigest()[:12].upper()}",
            "stage": ErrorStage.RIEC,
            "error_class": error_class,
            "code": code.value,
            "message": message,
            "recoverable": recoverable,
            "user_action": user_action,
            "safe_details": {},
            "cause_chain": (),
        }
    )


__all__ = ["RiecCoreResult", "run_grouped_riec_core"]
