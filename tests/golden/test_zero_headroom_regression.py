from __future__ import annotations

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from riec_guard.contract.models import ActionState, ProtocolId, ProtocolRole, ProtocolStatus
from riec_guard.contract.schema_loader import load_schema_registry
from riec_guard.decision.state_machine import ActionInputs, decide_action
from riec_guard.protocols.models import (
    G1Status,
    ProtocolComputation,
    StabilitySummary,
    SufficiencySummary,
    Uncertainty,
)


def _computation(
    protocol_id: ProtocolId,
    role: ProtocolRole,
    point_estimate: float | None,
    *,
    status: ProtocolStatus = ProtocolStatus.OK,
) -> ProtocolComputation:
    return ProtocolComputation(
        protocol_id=protocol_id,
        role=role,
        status=status,
        point_estimate=point_estimate,
        unit="mL" if role is ProtocolRole.HEADROOM else None,
        uncertainty=Uncertainty.none(),
        metrics=(),
        warnings=(),
        algorithm_notes="Phase D zero-headroom golden fixture",
    )


def test_phase_d_zero_headroom_regression_cannot_emit_zero_to_zero_pilot() -> None:
    inputs = ActionInputs(
        run_id="RUN-A1B2C3D4E5F6",
        contract_id="AC-123456789ABC",
        contract_valid=True,
        headroom_results=(
            _computation(
                ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE,
                ProtocolRole.HEADROOM,
                0.0,
            ),
        ),
        bootstrap=None,
        stability=StabilitySummary(
            computation=_computation(
                ProtocolId.G1_ORDERED_STABILITY_SCREEN,
                ProtocolRole.STABILITY_GATE,
                None,
                status=ProtocolStatus.WARNING,
            ),
            state=G1Status.MATERIAL_WARNING,
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
        near_tie=True,
        minimum_actionable_shift=0.1,
        maximum_screening_shift=1.0,
        measurement_resolution=0.01,
        protocol_spread_tolerance=0.5,
        unit="mL",
        evidence_ids=("EV-ACTION-123456789ABC",),
    )

    decision = decide_action(inputs)
    canonical = decision.to_canonical_dict()

    assert decision.state is ActionState.NO_ACTIONABLE_HEADROOM
    assert decision.pilot_reference is None
    assert decision.safe_headroom.value == 0.0
    assert decision.gates.zero_headroom_block is True
    Draft202012Validator(
        load_schema_registry().lookup("action_decision").validation_schema(),
        format_checker=FormatChecker(),
    ).validate(canonical)
