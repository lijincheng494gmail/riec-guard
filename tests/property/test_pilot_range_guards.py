from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

import pytest

from riec_guard.contract.models import (
    ActionState,
    ProtocolId,
    ProtocolRole,
    ProtocolStatus,
    UncertaintyKind,
)
from riec_guard.decision.state_machine import ActionInputs, ActionReasonCode, decide_action
from riec_guard.protocols.models import (
    BootstrapSummary,
    G1Status,
    ProtocolComputation,
    StabilitySummary,
    SufficiencySummary,
    Uncertainty,
)


def _computation(
    protocol_id: ProtocolId,
    role: ProtocolRole,
    point: float | None,
    *,
    status: ProtocolStatus = ProtocolStatus.OK,
) -> ProtocolComputation:
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
        warnings=(),
        algorithm_notes="test fixture",
    )


def _inputs(headroom: float | None = 0.45, *, near_tie: bool = False) -> ActionInputs:
    bootstrap = None
    if headroom is not None and headroom >= 0.0:
        bootstrap = BootstrapSummary(
            computation=_computation(
                ProtocolId.U1_GROUP_BOOTSTRAP_BOUND,
                ProtocolRole.UNCERTAINTY,
                headroom,
            ),
            lower_bounds=((ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE, headroom),),
            requested_replicates=200,
            successful_replicates=200,
            failed_replicates=0,
            failure_codes=(),
        )
    return ActionInputs(
        run_id="RUN-A1B2C3D4E5F6",
        contract_id="AC-123456789ABC",
        contract_valid=True,
        headroom_results=(
            _computation(
                ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE,
                ProtocolRole.HEADROOM,
                headroom,
            ),
        ),
        bootstrap=bootstrap,
        stability=StabilitySummary(
            computation=_computation(
                ProtocolId.G1_ORDERED_STABILITY_SCREEN,
                ProtocolRole.STABILITY_GATE,
                None,
            ),
            state=G1Status.PASS,
            ordered_coverage=1.0,
        ),
        sufficiency=SufficiencySummary(
            computation=_computation(
                ProtocolId.G2_EVIDENCE_SUFFICIENCY_GATE,
                ProtocolRole.EVIDENCE_GATE,
                None,
            ),
            exploratory_supported=True,
            action_supported=True,
            reason_codes=(),
        ),
        near_tie=near_tie,
        minimum_actionable_shift=0.1,
        maximum_screening_shift=1.0,
        measurement_resolution=0.01,
        protocol_spread_tolerance=0.5,
        unit="mL",
        evidence_ids=("EV-ACTION-123456789ABC",),
    )


def test_supported_pilot_uses_frozen_formula_and_decimal_safe_floor() -> None:
    decision = decide_action(_inputs())

    assert decision.state is ActionState.PILOT_RANGE_SUPPORTED
    assert decision.pilot_reference is not None
    assert decision.pilot_reference.lower == 0.13
    assert decision.pilot_reference.upper == 0.36
    assert decision.pilot_reference.rounding_mode == "down_to_measurement_resolution"
    assert decision.pilot_reference.screening_only is True


def test_conservative_pilot_matches_phase_d_golden_rounding() -> None:
    decision = decide_action(_inputs(near_tie=True))

    assert decision.state is ActionState.PILOT_ONLY_CONSERVATIVE
    assert decision.pilot_reference is not None
    assert decision.pilot_reference.lower == 0.1
    assert decision.pilot_reference.upper == 0.22


@pytest.mark.parametrize("headroom", (None, float("nan"), -0.1, 0.0, 0.05))
def test_null_nonfinite_nonpositive_and_subminimum_never_create_pilot(
    headroom: float | None,
) -> None:
    decision = decide_action(_inputs(headroom))

    assert decision.state is ActionState.NO_ACTIONABLE_HEADROOM
    assert decision.pilot_reference is None
    assert decision.gates.zero_headroom_block is True


def test_missing_resolution_downgrades_instead_of_inventing_rounding() -> None:
    decision = decide_action(replace(_inputs(), measurement_resolution=None))

    assert decision.state is ActionState.NO_ACTIONABLE_HEADROOM
    assert decision.pilot_reference is None
    assert decision.reason_codes == (ActionReasonCode.MEASUREMENT_RESOLUTION_UNAVAILABLE.value,)


def test_rounding_below_configured_minimum_downgrades() -> None:
    decision = decide_action(
        replace(
            _inputs(0.5, near_tie=True),
            minimum_actionable_shift=0.105,
            measurement_resolution=0.01,
        )
    )

    assert decision.state is ActionState.NO_ACTIONABLE_HEADROOM
    assert decision.pilot_reference is None
    assert decision.reason_codes == (ActionReasonCode.PILOT_RANGE_SUBMINIMUM.value,)


def test_inverted_supported_range_downgrades() -> None:
    decision = decide_action(
        replace(
            _inputs(1.0),
            maximum_screening_shift=0.2,
        )
    )

    assert decision.state is ActionState.NO_ACTIONABLE_HEADROOM
    assert decision.pilot_reference is None
    assert decision.reason_codes == (ActionReasonCode.PILOT_RANGE_INVERTED.value,)


def test_nonpositive_rounded_upper_downgrades() -> None:
    decision = decide_action(
        replace(
            _inputs(0.5),
            minimum_actionable_shift=0.0,
            maximum_screening_shift=0.005,
            measurement_resolution=0.01,
        )
    )

    assert decision.state is ActionState.NO_ACTIONABLE_HEADROOM
    assert decision.pilot_reference is None
    assert decision.reason_codes == (ActionReasonCode.PILOT_RANGE_NONPOSITIVE.value,)


@pytest.mark.parametrize(
    ("headroom", "resolution"),
    ((0.45, 0.01), (1.234, 0.1), (0.77, 0.05), (2.0, 0.25)),
)
def test_emitted_bounds_are_resolution_aligned(
    headroom: float,
    resolution: float,
) -> None:
    decision = decide_action(
        replace(
            _inputs(headroom),
            minimum_actionable_shift=resolution,
            maximum_screening_shift=10.0,
            measurement_resolution=resolution,
        )
    )

    assert decision.pilot_reference is not None
    lower_steps = Decimal(str(decision.pilot_reference.lower)) / Decimal(str(resolution))
    upper_steps = Decimal(str(decision.pilot_reference.upper)) / Decimal(str(resolution))
    assert lower_steps == lower_steps.to_integral_value()
    assert upper_steps == upper_steps.to_integral_value()
    assert 0 < decision.pilot_reference.lower <= decision.pilot_reference.upper
