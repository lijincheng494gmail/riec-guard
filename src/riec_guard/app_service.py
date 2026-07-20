"""Shared safe service for grouped RIEC-L1 and the Fill protocol/action layer."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace

from riec_guard.contract.models import (
    ActionDecision,
    AuditContract,
    CandidateDefinition,
    DatasetProfile,
    EvidenceProfile,
    OrderingStatus,
    ProtocolId,
    ProtocolResult,
    ProtocolRole,
    ProtocolStatus,
    UncertaintyKind,
    WarningSeverity,
)
from riec_guard.decision.state_machine import ActionInputs, decide_action
from riec_guard.domain.source import SourceRepository
from riec_guard.errors import ApplicationError, ErrorClass, ErrorEnvelope, ErrorStage
from riec_guard.evidence.ids import EvidenceError, create_evidence_item
from riec_guard.evidence.ledger import EvidenceLedgerBuilder
from riec_guard.evidence.models import (
    EvidenceComponent,
    EvidenceItem,
    EvidenceKind,
    EvidenceSourceRef,
    EvidenceStatus,
)
from riec_guard.protocols.empirical import run_empirical_headroom, run_mean_diagnostic
from riec_guard.protocols.gaussian_tail import run_gaussian_residual_tail
from riec_guard.protocols.group_bootstrap import run_group_bootstrap
from riec_guard.protocols.models import (
    BootstrapSummary,
    CrossFittedPrediction,
    Metric,
    ProtocolComputation,
    ProtocolReasonCode,
    Uncertainty,
    Warning,
)
from riec_guard.protocols.stability import run_ordered_stability_screen
from riec_guard.protocols.student_t_tail import run_student_t_residual_tail
from riec_guard.protocols.sufficiency import run_evidence_sufficiency_gate
from riec_guard.protocols.registry import EvidenceProfileConfig
from riec_guard.riec.design import (
    DesignFailure,
    PreparedDataset,
    build_prediction_design,
    build_training_design,
    prepare_dataset,
)
from riec_guard.riec.fit import FitFailure, fit_linear_model, predict_ols
from riec_guard.riec.grouped_cv import exact_logo_plan
from riec_guard.riec.registry import RunRegistrySnapshot, load_run_registry_snapshot
from riec_guard.riec.service import RiecCoreResult, run_grouped_riec_core
from riec_guard.settings import SeedSettings

_PROTOCOL_IMPLEMENTATION_VERSION = "fill-protocols.1.0.0"
_ACTION_IMPLEMENTATION_VERSION = "fill-action.1.0.0"
_DUMMY_ACTION_EVIDENCE_ID = "EV-ACTION-000000000000"


@dataclass(frozen=True, slots=True)
class FillProtocolActionResult:
    """Canonical public artifacts plus aggregate, row-free evidence items."""

    riec: RiecCoreResult
    protocols: ProtocolResult
    action: ActionDecision
    protocol_evidence: EvidenceItem
    action_evidence: EvidenceItem


class _FillFailure(ValueError):
    def __init__(
        self,
        code: str,
        *,
        stage: ErrorStage,
        error_class: ErrorClass,
        message: str,
        recoverable: bool,
        user_action: str,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.stage = stage
        self.error_class = error_class
        self.message = message
        self.recoverable = recoverable
        self.user_action = user_action


@dataclass(slots=True)
class AuditService:
    """One safe deterministic entry point shared by later CLI and UI layers."""

    settings: SeedSettings = SeedSettings()

    def seed_status(self) -> dict[str, str]:
        self.settings.assert_safe()
        return {"status": "seed", "next_task": "TASK-001"}

    def run_audit(
        self,
        repository: SourceRepository,
        *,
        run_id: str,
        source_id: str,
        contract: AuditContract,
        dataset_profile: DatasetProfile,
        registry_snapshot: RunRegistrySnapshot,
        evidence_builder: EvidenceLedgerBuilder | None = None,
    ) -> FillProtocolActionResult | ErrorEnvelope:
        """Run Macro-01 then the complete deterministic Macro-02 Fill layer.

        The service accepts no path, dynamic candidate list, protocol override,
        dependency installer, or raw rows.  The configured production bootstrap
        remains frozen at 200 replicates.
        """

        self.settings.assert_safe()
        try:
            return _run_fill_layer(
                repository,
                run_id=run_id,
                source_id=source_id,
                contract=contract,
                dataset_profile=dataset_profile,
                registry_snapshot=registry_snapshot,
                evidence_builder=evidence_builder,
            )
        except _FillFailure as error:
            return _error_envelope(error)
        except (EvidenceError, DesignFailure, FitFailure, ArithmeticError, TypeError, ValueError):
            return _error_envelope(
                _FillFailure(
                    "FILL_PROTOCOL_EXECUTION_FAILED",
                    stage=ErrorStage.PROTOCOL,
                    error_class=ErrorClass.INTERNAL,
                    message="The Fill protocol/action result could not be constructed safely.",
                    recoverable=False,
                    user_action=(
                        "Retry once; if the problem persists, preserve the safe error artifact."
                    ),
                )
            )


def _run_fill_layer(
    repository: SourceRepository,
    *,
    run_id: str,
    source_id: str,
    contract: AuditContract,
    dataset_profile: DatasetProfile,
    registry_snapshot: RunRegistrySnapshot,
    evidence_builder: EvidenceLedgerBuilder | None,
) -> FillProtocolActionResult | ErrorEnvelope:
    if (
        not isinstance(repository, SourceRepository)
        or not isinstance(contract, AuditContract)
        or not isinstance(dataset_profile, DatasetProfile)
        or not isinstance(registry_snapshot, RunRegistrySnapshot)
        or evidence_builder is not None
        and not isinstance(evidence_builder, EvidenceLedgerBuilder)
    ):
        raise _FillFailure(
            "FILL_TYPED_INPUT_INVALID",
            stage=ErrorStage.PROTOCOL,
            error_class=ErrorClass.VALIDATION,
            message="The Fill service received an invalid typed input.",
            recoverable=False,
            user_action="Use the canonical run, contract, profile, registry, and evidence types.",
        )

    trusted_profile = (
        load_run_registry_snapshot().evidence_profile.payload.to_contract_evidence_profile()
    )
    if contract.evidence_profile.to_canonical_dict() != trusted_profile.to_canonical_dict():
        raise _FillFailure(
            "FILL_EVIDENCE_PROFILE_MISMATCH",
            stage=ErrorStage.PROTOCOL,
            error_class=ErrorClass.SECURITY_BLOCK,
            message="The confirmed contract does not use the frozen Fill evidence profile.",
            recoverable=True,
            user_action="Rebuild and confirm the contract from the frozen evidence profile.",
        )

    core = run_grouped_riec_core(
        repository,
        run_id=run_id,
        source_id=source_id,
        contract=contract,
        dataset_profile=dataset_profile,
        registry_snapshot=registry_snapshot,
        evidence_builder=evidence_builder,
    )
    if isinstance(core, ErrorEnvelope):
        return core

    normalized = _trusted_normalized_bytes(
        repository,
        run_id=run_id,
        source_id=source_id,
        expected_sha256=core.dataset_sha256,
    )
    prepared = prepare_dataset(normalized, contract)
    selected_ids = tuple(core.decision.equivalence_set)
    cross_fitted = _cross_fitted_predictions(
        prepared,
        tuple(registry_snapshot.candidate_registry.payload.candidates),
        selected_ids,
    )

    policy = contract.policy
    profile = contract.evidence_profile
    profile_config = registry_snapshot.evidence_profile.payload
    unit = contract.measurement.unit
    d0 = run_mean_diagnostic(
        prepared.response,
        nominal_quantity=float(policy.nominal_quantity),
        lower_limit=float(policy.lower_limit),
        unit=unit,
    )
    h1 = run_empirical_headroom(
        prepared.response,
        prepared.group_tokens,
        lower_limit=float(policy.lower_limit),
        alpha=float(policy.alpha),
        unit=unit,
        min_rows=profile.min_rows,
        min_groups=profile.min_groups_exploratory,
        min_expected_tail_count=float(profile.min_expected_tail_count),
    )
    h2 = run_gaussian_residual_tail(
        prepared.response,
        prepared.group_tokens,
        cross_fitted,
        lower_limit=float(policy.lower_limit),
        alpha=float(policy.alpha),
        maximum_screening_shift=float(policy.maximum_screening_shift),
        unit=unit,
    )
    h3 = run_student_t_residual_tail(
        prepared.response,
        prepared.group_tokens,
        cross_fitted,
        lower_limit=float(policy.lower_limit),
        alpha=float(policy.alpha),
        maximum_screening_shift=float(policy.maximum_screening_shift),
        unit=unit,
    )
    initial_headrooms = (h1, h2, h3)
    bootstrap_ids = tuple(
        result.protocol_id for result in initial_headrooms if result.eligible_headroom
    )
    bootstrap = (
        _run_bootstrap(
            prepared,
            selected_candidates=tuple(registry_snapshot.candidate_registry.payload.candidates),
            selected_ids=selected_ids,
            protocol_ids=bootstrap_ids,
            contract=contract,
            profile_config=profile_config,
        )
        if bootstrap_ids
        else _bootstrap_without_eligible_protocol(unit, profile)
    )
    headrooms = tuple(_attach_bootstrap(result, bootstrap) for result in initial_headrooms)

    tie_break_keys = _tie_break_keys(normalized, contract)
    products = prepared.product.values or tuple("ALL" for _ in prepared.response)
    streams = prepared.stream.values or tuple("" for _ in prepared.response)
    times = prepared.time_hours or tuple(0.0 for _ in prepared.response)
    order_confirmed = (
        contract.ordering.status is OrderingStatus.CONFIRMED
        and contract.ordering.within_stream_order_confirmed
        and prepared.time_confirmed
        and prepared.time_hours is not None
    )
    stream_confirmed = prepared.stream.confirmed and prepared.stream.values is not None
    stability = run_ordered_stability_screen(
        prepared.response,
        products,
        streams,
        times,
        tie_break_keys,
        order_confirmed=order_confirmed,
        stream_confirmed=stream_confirmed,
        min_points_per_stream=profile.min_ordered_points_per_stream,
        minimum_coverage=float(profile.min_ordered_coverage),
    )
    measurement_valid = (
        contract.measurement.measurement_resolution is not None
        and float(contract.measurement.measurement_resolution) > 0.0
    )
    sufficiency = run_evidence_sufficiency_gate(
        n_rows=prepared.n_rows,
        n_groups=prepared.n_groups,
        alpha=float(policy.alpha),
        min_rows=profile.min_rows,
        min_groups_exploratory=profile.min_groups_exploratory,
        min_groups_action=profile.min_groups_action,
        min_expected_tail_count=float(profile.min_expected_tail_count),
        bootstrap_valid=bootstrap.valid,
        # A Fill action requires stability evidence; an unavailable G1 is explicit insufficiency.
        ordered_required=True,
        ordered_coverage=(
            stability.ordered_coverage if order_confirmed and stream_confirmed else None
        ),
        min_ordered_coverage=float(profile.min_ordered_coverage),
        measurement_valid=measurement_valid,
        product_support=_product_support(prepared),
    )

    computations = (
        d0,
        *headrooms,
        bootstrap.computation,
        stability.computation,
        sufficiency.computation,
    )
    protocol_evidence = _protocol_evidence_item(
        core=core,
        computations=computations,
        registry_snapshot=registry_snapshot,
        created_at=_created_at(contract),
        evidence_builder=evidence_builder,
    )
    protocols = ProtocolResult.model_validate(
        {
            "schema_version": "1.0.0",
            "run_id": core.artifact_run_id,
            "contract_id": contract.contract_id,
            "target_scope": {"product_id": "ALL", "stream_id": None},
            "results": tuple(
                result.to_canonical_entry(evidence_ids=(protocol_evidence.evidence_id,))
                for result in computations
            ),
        }
    )
    _verify_protocol_bundle(computations)

    material_state_conflict = any(result.eligible_headroom for result in headrooms) and any(
        result.status in {ProtocolStatus.INELIGIBLE, ProtocolStatus.FAILED} for result in headrooms
    )
    provisional_inputs = ActionInputs(
        run_id=core.artifact_run_id,
        contract_id=contract.contract_id,
        contract_valid=True,
        headroom_results=headrooms,
        bootstrap=bootstrap,
        stability=stability,
        sufficiency=sufficiency,
        near_tie=core.decision.near_tie,
        minimum_actionable_shift=float(policy.minimum_actionable_shift),
        maximum_screening_shift=float(policy.maximum_screening_shift),
        measurement_resolution=(
            None
            if contract.measurement.measurement_resolution is None
            else float(contract.measurement.measurement_resolution)
        ),
        protocol_spread_tolerance=float(policy.protocol_spread_tolerance),
        unit=unit,
        evidence_ids=(_DUMMY_ACTION_EVIDENCE_ID,),
        material_state_or_assumption_conflict=material_state_conflict,
    )
    provisional_action = decide_action(provisional_inputs)
    action_evidence = _action_evidence_item(
        core=core,
        action_payload=_without_evidence_ids(provisional_action.to_canonical_dict()),
        protocol_evidence=protocol_evidence,
        registry_snapshot=registry_snapshot,
        created_at=_created_at(contract),
        evidence_builder=evidence_builder,
    )
    action = decide_action(
        replace(
            provisional_inputs,
            evidence_ids=(
                action_evidence.evidence_id,
                core.evidence_item.evidence_id,
                protocol_evidence.evidence_id,
            ),
        )
    )

    return FillProtocolActionResult(
        riec=core,
        protocols=protocols,
        action=action,
        protocol_evidence=protocol_evidence,
        action_evidence=action_evidence,
    )


def _trusted_normalized_bytes(
    repository: SourceRepository,
    *,
    run_id: str,
    source_id: str,
    expected_sha256: str,
) -> bytes:
    try:
        source = repository.get_source(run_id, source_id)
        normalized = repository.read_normalized_bytes(run_id, source_id)
    except ApplicationError:
        raise _FillFailure(
            "FILL_SOURCE_UNAVAILABLE",
            stage=ErrorStage.PROTOCOL,
            error_class=ErrorClass.VALIDATION,
            message="The run-owned normalized source is unavailable for Fill protocols.",
            recoverable=True,
            user_action="Select the normalized source owned by the current run.",
        ) from None
    actual_sha256 = hashlib.sha256(normalized).hexdigest()
    if source.normalized_sha256 != actual_sha256 or actual_sha256 != expected_sha256:
        raise _FillFailure(
            "FILL_DATASET_MISMATCH",
            stage=ErrorStage.PROTOCOL,
            error_class=ErrorClass.SECURITY_BLOCK,
            message="The normalized source identity changed after grouped RIEC selection.",
            recoverable=False,
            user_action="Stop the run and re-profile the run-owned normalized source.",
        )
    return normalized


def _cross_fitted_predictions(
    dataset: PreparedDataset,
    candidates: tuple[CandidateDefinition, ...],
    selected_ids: tuple[str, ...],
) -> tuple[CrossFittedPrediction, ...]:
    if not selected_ids or len(set(selected_ids)) != len(selected_ids):
        raise _FillFailure(
            "FILL_SELECTION_SET_INVALID",
            stage=ErrorStage.PROTOCOL,
            error_class=ErrorClass.FIT_FAILURE,
            message="The frozen RIEC equivalence set is unavailable for residual protocols.",
            recoverable=False,
            user_action="Preserve the grouped RIEC result and retry the full analysis.",
        )
    by_id = {candidate.candidate_id: candidate for candidate in candidates}
    if any(candidate_id not in by_id for candidate_id in selected_ids):
        raise _FillFailure(
            "FILL_SELECTION_SET_INVALID",
            stage=ErrorStage.PROTOCOL,
            error_class=ErrorClass.SECURITY_BLOCK,
            message="The frozen RIEC equivalence set does not match the candidate registry.",
            recoverable=False,
            user_action="Use the immutable registry snapshot that produced the selection.",
        )
    folds = exact_logo_plan(dataset)
    outputs: list[CrossFittedPrediction] = []
    for candidate_id in selected_ids:
        predictions: list[float | None] = [None] * dataset.n_rows
        candidate = by_id[candidate_id]
        for _, train_indices, test_indices in folds:
            training = build_training_design(dataset, candidate, train_indices)
            test = build_prediction_design(dataset, training.specification, test_indices)
            fit = fit_linear_model(training.values, training.response)
            fold_predictions = predict_ols(fit, test.values)
            for row_index, prediction in zip(
                test.row_indices,
                fold_predictions,
                strict=True,
            ):
                if predictions[row_index] is not None:
                    raise _FillFailure(
                        "FILL_CROSSFIT_INVALID",
                        stage=ErrorStage.PROTOCOL,
                        error_class=ErrorClass.INTERNAL,
                        message="A cross-fitted row received more than one prediction.",
                        recoverable=False,
                        user_action="Preserve the safe error artifact for review.",
                    )
                predictions[row_index] = prediction
        complete: list[float] = []
        for stored_prediction in predictions:
            if stored_prediction is None:
                raise _FillFailure(
                    "FILL_CROSSFIT_INVALID",
                    stage=ErrorStage.PROTOCOL,
                    error_class=ErrorClass.INTERNAL,
                    message="Cross-fitted predictions are not exhaustive.",
                    recoverable=False,
                    user_action="Preserve the safe error artifact for review.",
                )
            complete.append(stored_prediction)
        outputs.append(
            CrossFittedPrediction(candidate_id=candidate_id, predictions=tuple(complete))
        )
    return tuple(outputs)


def _product_support(dataset: PreparedDataset) -> tuple[tuple[int, int], ...]:
    """Return label-free per-product row/group support for conservative G2 checks."""

    values = dataset.product.values
    if not dataset.product.confirmed or values is None:
        return ((dataset.n_rows, dataset.n_groups),)
    indices_by_product: dict[str, list[int]] = {}
    for index, value in enumerate(values):
        indices_by_product.setdefault(value, []).append(index)
    return tuple(
        (
            len(indices),
            len({dataset.group_tokens[index] for index in indices}),
        )
        for _, indices in sorted(indices_by_product.items())
    )


def _run_bootstrap(
    dataset: PreparedDataset,
    *,
    selected_candidates: tuple[CandidateDefinition, ...],
    selected_ids: tuple[str, ...],
    protocol_ids: tuple[ProtocolId, ...],
    contract: AuditContract,
    profile_config: EvidenceProfileConfig,
) -> BootstrapSummary:
    policy = contract.policy
    profile = contract.evidence_profile
    unit = contract.measurement.unit

    def evaluate(replicate: PreparedDataset) -> Mapping[ProtocolId, float]:
        needed_parametric = any(
            protocol_id
            in {
                ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL,
                ProtocolId.H3_STUDENT_T_RESIDUAL_TAIL,
            }
            for protocol_id in protocol_ids
        )
        replicate_crossfit = (
            _cross_fitted_predictions(replicate, selected_candidates, selected_ids)
            if needed_parametric
            else ()
        )
        results: dict[ProtocolId, ProtocolComputation] = {}
        if ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE in protocol_ids:
            results[ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE] = run_empirical_headroom(
                replicate.response,
                replicate.group_tokens,
                lower_limit=float(policy.lower_limit),
                alpha=float(policy.alpha),
                unit=unit,
                min_rows=profile.min_rows,
                min_groups=profile.min_groups_exploratory,
                min_expected_tail_count=float(profile.min_expected_tail_count),
            )
        if ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL in protocol_ids:
            results[ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL] = run_gaussian_residual_tail(
                replicate.response,
                replicate.group_tokens,
                replicate_crossfit,
                lower_limit=float(policy.lower_limit),
                alpha=float(policy.alpha),
                maximum_screening_shift=float(policy.maximum_screening_shift),
                unit=unit,
            )
        if ProtocolId.H3_STUDENT_T_RESIDUAL_TAIL in protocol_ids:
            results[ProtocolId.H3_STUDENT_T_RESIDUAL_TAIL] = run_student_t_residual_tail(
                replicate.response,
                replicate.group_tokens,
                replicate_crossfit,
                lower_limit=float(policy.lower_limit),
                alpha=float(policy.alpha),
                maximum_screening_shift=float(policy.maximum_screening_shift),
                unit=unit,
            )
        values: dict[ProtocolId, float] = {}
        for protocol_id in protocol_ids:
            result = results[protocol_id]
            if not result.eligible_headroom or result.point_estimate is None:
                raise ValueError("a bootstrap protocol replicate is ineligible")
            values[protocol_id] = result.point_estimate
        return values

    # The contract profile is bound above to this typed frozen config.
    config = profile_config
    return run_group_bootstrap(
        dataset,
        protocol_ids=protocol_ids,
        replicate_evaluator=evaluate,
        replicates=profile.bootstrap_replicates,
        seed=int(getattr(config, "bootstrap_seed")),
        confidence=float(profile.bootstrap_lower_confidence),
        min_groups=profile.min_groups_action,
        min_success=int(getattr(config, "bootstrap_min_success")),
        max_failed_fraction=float(profile.bootstrap_max_failure_fraction),
        unit=unit,
    )


def _bootstrap_without_eligible_protocol(
    unit: str,
    profile: EvidenceProfile,
) -> BootstrapSummary:
    warning = Warning(
        ProtocolReasonCode.BOOTSTRAP_INSUFFICIENT_SUCCESS,
        WarningSeverity.BLOCKING,
        "No eligible headroom protocol is available for conditional bootstrap uncertainty.",
    )
    computation = ProtocolComputation(
        protocol_id=ProtocolId.U1_GROUP_BOOTSTRAP_BOUND,
        role=ProtocolRole.UNCERTAINTY,
        status=ProtocolStatus.INELIGIBLE,
        point_estimate=None,
        unit=unit,
        uncertainty=Uncertainty(
            kind=UncertaintyKind.ONE_SIDED_LOWER,
            level=float(getattr(profile, "bootstrap_lower_confidence")),
            lower=None,
            upper=None,
            conditional_on_selection=True,
        ),
        metrics=(
            Metric("requested_replicates", int(getattr(profile, "bootstrap_replicates"))),
            Metric("successful_replicates", 0),
            Metric("failed_replicates", 0),
            Metric("conditional_on_selection", True),
        ),
        warnings=(warning,),
        algorithm_notes=(
            "Whole-group uncertainty is ineligible because no headroom protocol supplied a "
            "valid point estimate; candidate selection was not rerun."
        ),
    )
    return BootstrapSummary(
        computation=computation,
        lower_bounds=(),
        requested_replicates=int(getattr(profile, "bootstrap_replicates")),
        successful_replicates=0,
        failed_replicates=0,
        failure_codes=(warning.code.value,),
    )


def _attach_bootstrap(
    result: ProtocolComputation,
    bootstrap: BootstrapSummary,
) -> ProtocolComputation:
    lower = bootstrap.lower_bound(result.protocol_id) if bootstrap.valid else None
    if lower is None or not result.eligible_headroom:
        return result
    return result.with_uncertainty(
        Uncertainty(
            kind=UncertaintyKind.ONE_SIDED_LOWER,
            level=bootstrap.computation.uncertainty.level,
            lower=lower,
            upper=None,
            conditional_on_selection=True,
        )
    )


def _tie_break_keys(normalized: bytes, contract: AuditContract) -> tuple[tuple[str, ...], ...]:
    try:
        rows = tuple(
            tuple(cell.strip() for cell in row)
            for row in csv.reader(
                io.StringIO(normalized.decode("utf-8-sig", errors="strict"), newline=""),
                strict=True,
            )
        )
    except (UnicodeError, csv.Error):
        raise _FillFailure(
            "FILL_ORDER_INPUT_INVALID",
            stage=ErrorStage.PROTOCOL,
            error_class=ErrorClass.DATA_QUALITY,
            message="Confirmed tie-break columns could not be read safely.",
            recoverable=True,
            user_action="Normalize and reconfirm the ordered public CSV.",
        ) from None
    if not rows or len(rows) - 1 != contract.source.row_count:
        raise _FillFailure(
            "FILL_ORDER_INPUT_INVALID",
            stage=ErrorStage.PROTOCOL,
            error_class=ErrorClass.DATA_QUALITY,
            message="Confirmed ordered rows do not match the contract dimensions.",
            recoverable=True,
            user_action="Re-profile and reconfirm the ordered public CSV.",
        )
    header = rows[0]
    columns = tuple(contract.ordering.tie_break_columns)
    if any(column not in header for column in columns):
        raise _FillFailure(
            "FILL_ORDER_INPUT_INVALID",
            stage=ErrorStage.PROTOCOL,
            error_class=ErrorClass.DATA_QUALITY,
            message="A confirmed ordering tie-break column is unavailable.",
            recoverable=True,
            user_action="Reconfirm the ordering fields from the current profile.",
        )
    offsets = tuple(header.index(column) for column in columns)
    return tuple(tuple(row[offset] for offset in offsets) for row in rows[1:])


def _protocol_evidence_item(
    *,
    core: RiecCoreResult,
    computations: tuple[ProtocolComputation, ...],
    registry_snapshot: RunRegistrySnapshot,
    created_at: str,
    evidence_builder: EvidenceLedgerBuilder | None,
) -> EvidenceItem:
    value: dict[str, object] = {
        "target_scope": "ALL",
        "protocol_registry_id": registry_snapshot.protocol_registry.logical_id,
        "protocol_registry_version": registry_snapshot.protocol_registry.version,
        "evidence_profile_id": registry_snapshot.evidence_profile.logical_id,
        "evidence_profile_version": registry_snapshot.evidence_profile.version,
        "conditional_selection_ids": list(core.decision.equivalence_set),
        "results": [_evidence_protocol_result(result) for result in computations],
        "implementation_version": _PROTOCOL_IMPLEMENTATION_VERSION,
    }
    status = (
        EvidenceStatus.MATERIAL
        if any(result.material_warning for result in computations)
        else EvidenceStatus.WARNING
        if any(result.status is not ProtocolStatus.OK for result in computations)
        else EvidenceStatus.OK
    )
    return _materialize_evidence(
        evidence_builder,
        component=EvidenceComponent.PROTOCOL,
        kind=EvidenceKind.STATISTIC,
        status=status,
        statement=("The complete frozen Fill protocol library and evidence gates were evaluated."),
        value=value,
        unit=None,
        source_refs=(
            EvidenceSourceRef.model_validate(
                {
                    "artifact_id": "normalized.dataset",
                    "artifact_sha256": core.dataset_sha256,
                    "locator": "run-owned-normalized-csv",
                }
            ),
            EvidenceSourceRef.model_validate(
                {
                    "artifact_id": "protocol.registry",
                    "artifact_sha256": registry_snapshot.protocol_registry.canonical_json_sha256,
                    "locator": registry_snapshot.protocol_registry.logical_id,
                }
            ),
            EvidenceSourceRef.model_validate(
                {
                    "artifact_id": "evidence.profile",
                    "artifact_sha256": registry_snapshot.evidence_profile.canonical_json_sha256,
                    "locator": registry_snapshot.evidence_profile.logical_id,
                }
            ),
        ),
        parent_evidence_ids=(core.evidence_item.evidence_id,),
        input_sha256=core.dataset_sha256,
        contract_sha256=core.contract_sha256,
        implementation_version=_PROTOCOL_IMPLEMENTATION_VERSION,
        created_at=created_at,
    )


def _action_evidence_item(
    *,
    core: RiecCoreResult,
    action_payload: dict[str, object],
    protocol_evidence: EvidenceItem,
    registry_snapshot: RunRegistrySnapshot,
    created_at: str,
    evidence_builder: EvidenceLedgerBuilder | None,
) -> EvidenceItem:
    return _materialize_evidence(
        evidence_builder,
        component=EvidenceComponent.ACTION,
        kind=EvidenceKind.DECISION_REASON,
        status=_action_evidence_status(str(action_payload["state"])),
        statement="The ordered six-state Fill action engine returned one bounded outcome.",
        value={
            "decision": action_payload,
            "implementation_version": _ACTION_IMPLEMENTATION_VERSION,
        },
        unit=None,
        source_refs=(
            EvidenceSourceRef.model_validate(
                {
                    "artifact_id": "policy.registry",
                    "artifact_sha256": registry_snapshot.policy_registry.canonical_json_sha256,
                    "locator": registry_snapshot.policy_registry.logical_id,
                }
            ),
            EvidenceSourceRef.model_validate(
                {
                    "artifact_id": "claim.ruleset",
                    "artifact_sha256": registry_snapshot.claim_ruleset.canonical_json_sha256,
                    "locator": registry_snapshot.claim_ruleset.logical_id,
                }
            ),
        ),
        parent_evidence_ids=tuple(
            sorted((core.evidence_item.evidence_id, protocol_evidence.evidence_id))
        ),
        input_sha256=core.dataset_sha256,
        contract_sha256=core.contract_sha256,
        implementation_version=_ACTION_IMPLEMENTATION_VERSION,
        created_at=created_at,
    )


def _materialize_evidence(
    builder: EvidenceLedgerBuilder | None,
    *,
    component: EvidenceComponent,
    kind: EvidenceKind,
    status: EvidenceStatus,
    statement: str,
    value: dict[str, object],
    unit: str | None,
    source_refs: Sequence[EvidenceSourceRef],
    parent_evidence_ids: Sequence[str],
    input_sha256: str,
    contract_sha256: str,
    implementation_version: str,
    created_at: str,
) -> EvidenceItem:
    fields = {
        "component": component,
        "kind": kind,
        "status": status,
        "statement": statement,
        "value": value,
        "unit": unit,
        "source_refs": source_refs,
        "parent_evidence_ids": parent_evidence_ids,
        "input_sha256": input_sha256,
        "contract_sha256": contract_sha256,
        "implementation_version": implementation_version,
        "created_at": created_at,
    }
    prospective = create_evidence_item(**fields)  # type: ignore[arg-type]
    if builder is None:
        return prospective
    appended = builder.append_new(**fields)  # type: ignore[arg-type]
    if appended.item.evidence_id != prospective.evidence_id:
        raise _FillFailure(
            "FILL_EVIDENCE_IDENTITY_CHANGED",
            stage=ErrorStage.PROTOCOL,
            error_class=ErrorClass.SECURITY_BLOCK,
            message="Aggregate Fill evidence identity changed during run binding.",
            recoverable=False,
            user_action="Stop the run and preserve the safe error artifact for review.",
        )
    return appended.item


def _evidence_protocol_result(result: ProtocolComputation) -> dict[str, object]:
    return {
        "protocol_id": result.protocol_id.value,
        "role": result.role.value,
        "status": result.status.value,
        "point_estimate": result.point_estimate,
        "unit": result.unit,
        "uncertainty": {
            "kind": result.uncertainty.kind.value,
            "level": result.uncertainty.level,
            "lower": result.uncertainty.lower,
            "upper": result.uncertainty.upper,
            "conditional_on_selection": result.uncertainty.conditional_on_selection,
        },
        "metrics": [
            {
                "name": metric.name,
                "value": list(metric.value) if isinstance(metric.value, tuple) else metric.value,
                "unit": metric.unit,
            }
            for metric in result.metrics
        ],
        "warnings": [
            {
                "code": warning.code.value,
                "severity": warning.severity.value,
            }
            for warning in result.warnings
        ],
    }


def _verify_protocol_bundle(computations: tuple[ProtocolComputation, ...]) -> None:
    expected = (
        ProtocolId.D0_MEAN_DIAGNOSTIC,
        ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE,
        ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL,
        ProtocolId.H3_STUDENT_T_RESIDUAL_TAIL,
        ProtocolId.U1_GROUP_BOOTSTRAP_BOUND,
        ProtocolId.G1_ORDERED_STABILITY_SCREEN,
        ProtocolId.G2_EVIDENCE_SUFFICIENCY_GATE,
    )
    actual = tuple(result.protocol_id for result in computations)
    if actual != expected or len(set(actual)) != len(expected):
        raise _FillFailure(
            "FILL_PROTOCOL_BUNDLE_INVALID",
            stage=ErrorStage.PROTOCOL,
            error_class=ErrorClass.INTERNAL,
            message="The canonical Fill protocol bundle is incomplete or out of order.",
            recoverable=False,
            user_action="Preserve the safe error artifact for review.",
        )


def _without_evidence_ids(value: dict[str, object]) -> dict[str, object]:
    result = dict(value)
    result.pop("evidence_ids", None)
    # Runtime run ownership is carried by the builder/ledger, not hashed into the
    # reusable aggregate decision evidence content.
    result.pop("run_id", None)
    return result


def _action_evidence_status(state: str) -> EvidenceStatus:
    if state == "pilot_range_supported":
        return EvidenceStatus.OK
    if state in {"pilot_only_conservative", "diagnose_process_first"}:
        return EvidenceStatus.MATERIAL
    if state == "invalid_contract":
        return EvidenceStatus.BLOCKING
    return EvidenceStatus.WARNING


def _created_at(contract: AuditContract) -> str:
    created_at = contract.confirmation.confirmed_at or contract.created_at
    if created_at is None:
        raise _FillFailure(
            "FILL_CONTRACT_TIMESTAMP_MISSING",
            stage=ErrorStage.CONTRACT,
            error_class=ErrorClass.VALIDATION,
            message="A confirmed contract timestamp is required for Fill evidence.",
            recoverable=True,
            user_action="Reconfirm the contract with a canonical timestamp.",
        )
    return created_at


def _error_envelope(error: _FillFailure) -> ErrorEnvelope:
    identity = json.dumps(
        {
            "code": error.code,
            "error_class": error.error_class.value,
            "stage": error.stage.value,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return ErrorEnvelope.model_validate(
        {
            "schema_version": "1.0.0",
            "error_id": f"ERR-{hashlib.sha256(identity).hexdigest()[:12].upper()}",
            "stage": error.stage,
            "error_class": error.error_class,
            "code": error.code,
            "message": error.message,
            "recoverable": error.recoverable,
            "user_action": error.user_action,
            "safe_details": {},
            "cause_chain": (),
        }
    )


__all__ = ["AuditService", "FillProtocolActionResult"]
