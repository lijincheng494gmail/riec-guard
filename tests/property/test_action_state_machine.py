from __future__ import annotations

from dataclasses import replace

import pytest

from riec_guard.contract.models import (
    ActionState,
    HeadroomBasis,
    ProtocolId,
    ProtocolRole,
    ProtocolStatus,
    UncertaintyKind,
    WarningSeverity,
)
from riec_guard.decision.state_machine import (
    ActionInputs,
    ActionReasonCode,
    decide_action,
    evaluate_action,
)
from riec_guard.protocols.models import (
    BootstrapSummary,
    G1Status,
    ProtocolComputation,
    ProtocolReasonCode,
    StabilitySummary,
    SufficiencySummary,
    Uncertainty,
    Warning,
)

RUN_ID = "RUN-A1B2C3D4E5F6"
CONTRACT_ID = "AC-123456789ABC"
EVIDENCE_IDS = ("EV-ACTION-123456789ABC",)


def _computation(
    protocol_id: ProtocolId,
    *,
    point: float | None = None,
    status: ProtocolStatus = ProtocolStatus.OK,
    warning: Warning | None = None,
) -> ProtocolComputation:
    role = {
        ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE: ProtocolRole.HEADROOM,
        ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL: ProtocolRole.HEADROOM,
        ProtocolId.H3_STUDENT_T_RESIDUAL_TAIL: ProtocolRole.HEADROOM,
        ProtocolId.U1_GROUP_BOOTSTRAP_BOUND: ProtocolRole.UNCERTAINTY,
        ProtocolId.G1_ORDERED_STABILITY_SCREEN: ProtocolRole.STABILITY_GATE,
        ProtocolId.G2_EVIDENCE_SUFFICIENCY_GATE: ProtocolRole.EVIDENCE_GATE,
    }[protocol_id]
    return ProtocolComputation(
        protocol_id=protocol_id,
        role=role,
        status=status,
        point_estimate=point,
        unit="mL" if role is ProtocolRole.HEADROOM else None,
        uncertainty=(
            Uncertainty(
                kind=UncertaintyKind.ONE_SIDED_LOWER,
                level=0.9,
                lower=point,
                upper=None,
                conditional_on_selection=True,
            )
            if role is ProtocolRole.UNCERTAINTY
            else Uncertainty.none()
        ),
        metrics=(),
        warnings=() if warning is None else (warning,),
        algorithm_notes="test fixture",
    )


def _inputs(
    *,
    contract_valid: bool = True,
    action_supported: bool = True,
    headroom: float | None = 0.5,
    stability: G1Status = G1Status.PASS,
    near_tie: bool = False,
    spread_tolerance: float = 0.5,
    headroom_results: tuple[ProtocolComputation, ...] | None = None,
    bootstrap: BootstrapSummary | None = None,
    with_default_bootstrap: bool = True,
    material_state_conflict: bool = False,
) -> ActionInputs:
    resolved_headrooms = (
        (_computation(ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE, point=headroom),)
        if headroom_results is None
        else headroom_results
    )
    if bootstrap is None and with_default_bootstrap:
        bounds = tuple(
            (result.protocol_id, result.point_estimate)
            for result in resolved_headrooms
            if result.eligible_headroom and result.point_estimate is not None
        )
        if bounds:
            bootstrap = BootstrapSummary(
                computation=_computation(
                    ProtocolId.U1_GROUP_BOOTSTRAP_BOUND,
                    point=min(value for _, value in bounds),
                ),
                lower_bounds=bounds,
                requested_replicates=200,
                successful_replicates=200,
                failed_replicates=0,
                failure_codes=(),
            )
    stability_computation = _computation(
        ProtocolId.G1_ORDERED_STABILITY_SCREEN,
        status=(
            ProtocolStatus.INELIGIBLE
            if stability is G1Status.INELIGIBLE
            else ProtocolStatus.WARNING
            if stability is G1Status.MATERIAL_WARNING
            else ProtocolStatus.OK
        ),
    )
    sufficiency_computation = _computation(
        ProtocolId.G2_EVIDENCE_SUFFICIENCY_GATE,
        status=ProtocolStatus.OK if action_supported else ProtocolStatus.INELIGIBLE,
    )
    return ActionInputs(
        run_id=RUN_ID,
        contract_id=CONTRACT_ID,
        contract_valid=contract_valid,
        headroom_results=resolved_headrooms,
        bootstrap=bootstrap,
        stability=StabilitySummary(
            computation=stability_computation,
            state=stability,
            ordered_coverage=1.0,
        ),
        sufficiency=SufficiencySummary(
            computation=sufficiency_computation,
            exploratory_supported=action_supported,
            action_supported=action_supported,
            reason_codes=(),
        ),
        near_tie=near_tie,
        minimum_actionable_shift=0.1,
        maximum_screening_shift=1.0,
        measurement_resolution=0.01,
        protocol_spread_tolerance=spread_tolerance,
        unit="mL",
        evidence_ids=EVIDENCE_IDS,
        material_state_or_assumption_conflict=material_state_conflict,
    )


@pytest.mark.parametrize(
    ("inputs", "expected"),
    (
        (
            _inputs(
                contract_valid=False,
                action_supported=False,
                headroom=0.0,
                stability=G1Status.MATERIAL_WARNING,
                near_tie=True,
            ),
            ActionState.INVALID_CONTRACT,
        ),
        (
            _inputs(
                action_supported=False,
                headroom=0.0,
                stability=G1Status.MATERIAL_WARNING,
                near_tie=True,
            ),
            ActionState.INSUFFICIENT_EVIDENCE,
        ),
        (
            _inputs(
                headroom=0.0,
                stability=G1Status.MATERIAL_WARNING,
                near_tie=True,
            ),
            ActionState.NO_ACTIONABLE_HEADROOM,
        ),
        (
            _inputs(stability=G1Status.MATERIAL_WARNING, near_tie=True),
            ActionState.DIAGNOSE_PROCESS_FIRST,
        ),
        (_inputs(near_tie=True), ActionState.PILOT_ONLY_CONSERVATIVE),
        (_inputs(), ActionState.PILOT_RANGE_SUPPORTED),
    ),
)
def test_first_trigger_wins_and_exactly_one_state(
    inputs: ActionInputs,
    expected: ActionState,
) -> None:
    evaluation = evaluate_action(inputs)
    decision = decide_action(inputs)

    assert evaluation.state is expected
    assert decision.state is expected
    assert isinstance(decision.state, ActionState)
    assert decision.reason_codes
    assert evaluation.reason_codes


def test_bootstrap_lower_bounds_are_preferred_and_aggregated_by_minimum() -> None:
    h1 = _computation(ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE, point=0.8)
    h2 = _computation(ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL, point=0.9)
    u1 = _computation(ProtocolId.U1_GROUP_BOOTSTRAP_BOUND, point=0.6)
    bootstrap = BootstrapSummary(
        computation=u1,
        lower_bounds=(
            (ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE, 0.55),
            (ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL, 0.65),
        ),
        requested_replicates=200,
        successful_replicates=200,
        failed_replicates=0,
        failure_codes=(),
    )

    decision = decide_action(
        _inputs(headroom_results=(h2, h1), bootstrap=bootstrap, spread_tolerance=0.2)
    )

    assert decision.safe_headroom.value == 0.55
    assert decision.safe_headroom.basis is HeadroomBasis.BOOTSTRAP_LOWER_BOUNDS
    assert tuple(item.value for item in decision.safe_headroom.eligible_protocol_ids) == (
        "H1_group_empirical_quantile",
        "H2_gaussian_residual_tail",
    )
    assert decision.conflict.protocol_spread == pytest.approx(0.1)


def test_missing_one_bootstrap_bound_is_explicitly_unbounded_basis() -> None:
    h1 = _computation(ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE, point=0.8)
    h2 = _computation(ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL, point=0.9)
    bootstrap = BootstrapSummary(
        computation=_computation(ProtocolId.U1_GROUP_BOOTSTRAP_BOUND, point=0.7),
        lower_bounds=((ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE, 0.7),),
        requested_replicates=200,
        successful_replicates=200,
        failed_replicates=0,
        failure_codes=(),
    )

    decision = decide_action(_inputs(headroom_results=(h1, h2), bootstrap=bootstrap))

    assert decision.safe_headroom.value == 0.7
    assert decision.safe_headroom.basis is HeadroomBasis.POINT_ESTIMATES_WITHOUT_BOUND
    assert decision.state is ActionState.PILOT_ONLY_CONSERVATIVE
    assert ActionReasonCode.UNCERTAINTY_BOUND_UNAVAILABLE.value in decision.reason_codes


def test_point_estimates_without_bootstrap_cannot_receive_strongest_state() -> None:
    decision = decide_action(_inputs(with_default_bootstrap=False))

    assert decision.state is ActionState.PILOT_ONLY_CONSERVATIVE
    assert decision.safe_headroom.basis is HeadroomBasis.POINT_ESTIMATES_WITHOUT_BOUND
    assert ActionReasonCode.UNCERTAINTY_BOUND_UNAVAILABLE.value in decision.reason_codes


def test_spread_near_tie_and_parametric_warning_use_closed_reason_order() -> None:
    material_warning = Warning(
        code=ProtocolReasonCode.RESIDUAL_SKEW_DIAGNOSTIC,
        severity=WarningSeverity.MATERIAL,
        message="material residual skew diagnostic",
    )
    h1 = _computation(ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE, point=0.2)
    h2 = _computation(
        ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL,
        point=0.8,
        warning=material_warning,
    )

    decision = decide_action(
        _inputs(
            headroom_results=(h1, h2),
            near_tie=True,
            spread_tolerance=0.1,
            material_state_conflict=True,
        )
    )

    assert decision.state is ActionState.PILOT_ONLY_CONSERVATIVE
    assert decision.conflict.material_protocol_conflict is True
    assert decision.conflict.near_tie is True
    assert tuple(decision.reason_codes) == tuple(
        code.value
        for code in (
            ActionReasonCode.PROTOCOL_SPREAD_MATERIAL,
            ActionReasonCode.PROTOCOL_STATE_OR_ASSUMPTION_CONFLICT,
            ActionReasonCode.RIEC_NEAR_TIE,
            ActionReasonCode.PARAMETRIC_DIAGNOSTIC_MATERIAL,
            ActionReasonCode.CONSERVATIVE_PILOT_REFERENCE,
        )
    )


def test_evidence_ids_and_retrospective_claim_boundary_are_preserved() -> None:
    inputs = replace(
        _inputs(),
        evidence_ids=(
            "EV-RIEC-123456789ABC",
            "EV-PROTOCOL-ABCDEF123456",
            "EV-ACTION-0A1B2C3D4E5F",
        ),
    )

    decision = decide_action(inputs)
    boundary_text = " ".join(
        (*decision.claim_boundary.allowed, *decision.claim_boundary.conditional)
    )

    assert decision.evidence_ids == inputs.evidence_ids
    assert "retrospective screening reference" in boundary_text
    assert decision.reason_codes == (ActionReasonCode.SUPPORTED_PILOT_REFERENCE.value,)


def test_action_inputs_reject_duplicate_evidence_ids() -> None:
    with pytest.raises(ValueError, match="unique"):
        replace(
            _inputs(),
            evidence_ids=("EV-ACTION-123456789ABC", "EV-ACTION-123456789ABC"),
        )


def test_action_inputs_reject_mislabeled_gate_and_bootstrap_summaries() -> None:
    base = _inputs()
    with pytest.raises(ValueError, match="frozen G1"):
        replace(
            base,
            stability=StabilitySummary(
                computation=_computation(
                    ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE,
                    point=0.5,
                ),
                state=G1Status.PASS,
                ordered_coverage=1.0,
            ),
        )

    assert base.bootstrap is not None
    with pytest.raises(ValueError, match="conditional frozen U1"):
        replace(
            base,
            bootstrap=replace(
                base.bootstrap,
                computation=_computation(
                    ProtocolId.G1_ORDERED_STABILITY_SCREEN,
                    status=ProtocolStatus.OK,
                ),
            ),
        )
