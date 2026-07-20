"""Pure six-state action engine and bounded pilot-reference construction.

The engine consumes deterministic protocol summaries only.  It does not read
data, fit models, mutate evidence, or infer policy.  The order implemented here
is frozen: invalid contract, insufficient evidence, no actionable headroom,
diagnose process first, conservative pilot, supported pilot.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_FLOOR
from enum import StrEnum

from riec_guard.contract.models import (
    ActionDecision,
    ActionGates,
    ActionState,
    ClaimBoundary,
    HeadroomBasis,
    HeadroomProtocolId,
    OrderedStability,
    PilotReference,
    ProtocolConflict,
    ProtocolId,
    ProtocolRole,
    ProtocolStatus,
    SafeHeadroom,
)
from riec_guard.protocols.models import (
    BootstrapSummary,
    G1Status,
    ProtocolComputation,
    StabilitySummary,
    SufficiencySummary,
)

_HEADROOM_PROTOCOL_ORDER = (
    ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE,
    ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL,
    ProtocolId.H3_STUDENT_T_RESIDUAL_TAIL,
)
_PARAMETRIC_PROTOCOLS = {
    ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL,
    ProtocolId.H3_STUDENT_T_RESIDUAL_TAIL,
}


class ActionReasonCode(StrEnum):
    """Closed implementation-v1 reason vocabulary in stable output order."""

    CONTRACT_INVALID = "CONTRACT_INVALID"
    EVIDENCE_INSUFFICIENT = "EVIDENCE_INSUFFICIENT"
    NO_ELIGIBLE_HEADROOM = "NO_ELIGIBLE_HEADROOM"
    HEADROOM_NONPOSITIVE = "HEADROOM_NONPOSITIVE"
    HEADROOM_BELOW_MINIMUM_ACTIONABLE = "HEADROOM_BELOW_MINIMUM_ACTIONABLE"
    MEASUREMENT_RESOLUTION_UNAVAILABLE = "MEASUREMENT_RESOLUTION_UNAVAILABLE"
    PILOT_RANGE_NONPOSITIVE = "PILOT_RANGE_NONPOSITIVE"
    PILOT_RANGE_SUBMINIMUM = "PILOT_RANGE_SUBMINIMUM"
    PILOT_RANGE_INVERTED = "PILOT_RANGE_INVERTED"
    ORDERED_STABILITY_MATERIAL_WARNING = "ORDERED_STABILITY_MATERIAL_WARNING"
    PROTOCOL_SPREAD_MATERIAL = "PROTOCOL_SPREAD_MATERIAL"
    PROTOCOL_STATE_OR_ASSUMPTION_CONFLICT = "PROTOCOL_STATE_OR_ASSUMPTION_CONFLICT"
    RIEC_NEAR_TIE = "RIEC_NEAR_TIE"
    PARAMETRIC_DIAGNOSTIC_MATERIAL = "PARAMETRIC_DIAGNOSTIC_MATERIAL"
    UNCERTAINTY_BOUND_UNAVAILABLE = "UNCERTAINTY_BOUND_UNAVAILABLE"
    CONSERVATIVE_PILOT_REFERENCE = "CONSERVATIVE_PILOT_REFERENCE"
    SUPPORTED_PILOT_REFERENCE = "SUPPORTED_PILOT_REFERENCE"


@dataclass(frozen=True, slots=True)
class ActionInputs:
    """All already-validated deterministic inputs needed by the action engine."""

    run_id: str
    contract_id: str
    contract_valid: bool
    headroom_results: tuple[ProtocolComputation, ...]
    bootstrap: BootstrapSummary | None
    stability: StabilitySummary
    sufficiency: SufficiencySummary
    near_tie: bool
    minimum_actionable_shift: float
    maximum_screening_shift: float
    measurement_resolution: float | None
    protocol_spread_tolerance: float
    unit: str
    evidence_ids: tuple[str, ...]
    material_state_or_assumption_conflict: bool = False

    def __post_init__(self) -> None:
        if not self.run_id or not self.contract_id:
            raise ValueError("run_id and contract_id are required")
        if not self.unit:
            raise ValueError("unit is required")
        if not self.evidence_ids:
            raise ValueError("at least one evidence ID is required")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("evidence IDs must be unique")
        if type(self.contract_valid) is not bool or type(self.near_tie) is not bool:
            raise ValueError("contract_valid and near_tie must be booleans")
        if type(self.material_state_or_assumption_conflict) is not bool:
            raise ValueError("material conflict flag must be boolean")
        if not isinstance(self.stability, StabilitySummary) or not isinstance(
            self.sufficiency, SufficiencySummary
        ):
            raise ValueError("typed stability and sufficiency summaries are required")
        if any(not isinstance(result, ProtocolComputation) for result in self.headroom_results):
            raise ValueError("typed headroom computations are required")
        protocol_ids = tuple(result.protocol_id for result in self.headroom_results)
        if len(set(protocol_ids)) != len(protocol_ids) or any(
            protocol_id not in _HEADROOM_PROTOCOL_ORDER for protocol_id in protocol_ids
        ):
            raise ValueError("headroom results must contain unique frozen H1/H2/H3 IDs")
        if any(result.role.value != "headroom" for result in self.headroom_results):
            raise ValueError("action headroom inputs must retain the headroom role")
        _validate_summary_provenance(self)
        _require_finite_nonnegative(self.minimum_actionable_shift, "minimum_actionable_shift")
        _require_finite_positive(self.maximum_screening_shift, "maximum_screening_shift")
        _require_finite_nonnegative(self.protocol_spread_tolerance, "protocol_spread_tolerance")
        if self.measurement_resolution is not None:
            _require_finite_positive(self.measurement_resolution, "measurement_resolution")


@dataclass(frozen=True, slots=True)
class SafeHeadroomSummary:
    """Conservative values and their frozen aggregate minimum."""

    value: float | None
    basis: HeadroomBasis
    eligible_protocol_ids: tuple[HeadroomProtocolId, ...]
    conservative_values: tuple[tuple[HeadroomProtocolId, float], ...]


@dataclass(frozen=True, slots=True)
class PilotRange:
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class ActionEvaluation:
    """Internal immutable decision, before projection to the canonical model."""

    state: ActionState
    reason_codes: tuple[ActionReasonCode, ...]
    safe_headroom: SafeHeadroomSummary
    pilot_range: PilotRange | None
    conflict: ProtocolConflict
    zero_headroom_block: bool


def summarize_safe_headroom(inputs: ActionInputs) -> SafeHeadroomSummary:
    """Apply valid U1 lower bounds when present, otherwise protocol points."""

    by_id = {result.protocol_id: result for result in inputs.headroom_results}
    values: list[tuple[HeadroomProtocolId, float]] = []
    all_values_bounded = inputs.bootstrap is not None and inputs.bootstrap.valid

    for protocol_id in _HEADROOM_PROTOCOL_ORDER:
        result = by_id.get(protocol_id)
        if result is None or not result.eligible_headroom:
            continue

        canonical_id = HeadroomProtocolId(protocol_id.value)
        lower_bound = _valid_bootstrap_lower_bound(inputs.bootstrap, protocol_id)
        if lower_bound is None:
            all_values_bounded = False
            # eligible_headroom proves this is finite and non-null.
            assert result.point_estimate is not None
            conservative_value = result.point_estimate
        else:
            conservative_value = lower_bound
        values.append((canonical_id, conservative_value))

    if not values:
        return SafeHeadroomSummary(
            value=None,
            basis=HeadroomBasis.NONE,
            eligible_protocol_ids=(),
            conservative_values=(),
        )

    return SafeHeadroomSummary(
        value=min(value for _, value in values),
        basis=(
            HeadroomBasis.BOOTSTRAP_LOWER_BOUNDS
            if all_values_bounded
            else HeadroomBasis.POINT_ESTIMATES_WITHOUT_BOUND
        ),
        eligible_protocol_ids=tuple(protocol_id for protocol_id, _ in values),
        conservative_values=tuple(values),
    )


def evaluate_action(inputs: ActionInputs) -> ActionEvaluation:
    """Evaluate the frozen first-trigger-wins state machine without side effects."""

    safe = summarize_safe_headroom(inputs)
    parametric_warning = _has_material_parametric_warning(inputs.headroom_results)
    conflict, conflict_reasons = _summarize_conflict(inputs, safe, parametric_warning)
    headroom_reason = _headroom_guard_reason(safe.value, inputs.minimum_actionable_shift)

    if not inputs.contract_valid:
        return _evaluation(
            ActionState.INVALID_CONTRACT,
            (ActionReasonCode.CONTRACT_INVALID,),
            safe,
            None,
            conflict,
            headroom_reason is not None,
        )

    if not inputs.sufficiency.action_supported:
        return _evaluation(
            ActionState.INSUFFICIENT_EVIDENCE,
            (ActionReasonCode.EVIDENCE_INSUFFICIENT,),
            safe,
            None,
            conflict,
            headroom_reason is not None,
        )

    if headroom_reason is not None:
        return _evaluation(
            ActionState.NO_ACTIONABLE_HEADROOM,
            (headroom_reason,),
            safe,
            None,
            conflict,
            True,
        )

    if inputs.stability.state is G1Status.MATERIAL_WARNING:
        return _evaluation(
            ActionState.DIAGNOSE_PROCESS_FIRST,
            (ActionReasonCode.ORDERED_STABILITY_MATERIAL_WARNING,),
            safe,
            None,
            conflict,
            False,
        )

    point_estimates_without_bound = (
        safe.value is not None and safe.basis is HeadroomBasis.POINT_ESTIMATES_WITHOUT_BOUND
    )
    conservative = (
        conflict.material_protocol_conflict
        or inputs.near_tie
        or parametric_warning
        or point_estimates_without_bound
    )
    state = (
        ActionState.PILOT_ONLY_CONSERVATIVE if conservative else ActionState.PILOT_RANGE_SUPPORTED
    )
    pilot_range, pilot_guard = _construct_pilot_range(
        state=state,
        safe_headroom=safe.value,
        minimum_actionable_shift=inputs.minimum_actionable_shift,
        maximum_screening_shift=inputs.maximum_screening_shift,
        measurement_resolution=inputs.measurement_resolution,
    )
    if pilot_guard is not None:
        return _evaluation(
            ActionState.NO_ACTIONABLE_HEADROOM,
            (pilot_guard,),
            safe,
            None,
            conflict,
            True,
        )

    assert pilot_range is not None
    reasons = (
        _ordered_unique_reasons(
            (
                *conflict_reasons,
                *(
                    (ActionReasonCode.UNCERTAINTY_BOUND_UNAVAILABLE,)
                    if point_estimates_without_bound
                    else ()
                ),
                ActionReasonCode.CONSERVATIVE_PILOT_REFERENCE,
            )
        )
        if conservative
        else (ActionReasonCode.SUPPORTED_PILOT_REFERENCE,)
    )
    return _evaluation(state, reasons, safe, pilot_range, conflict, False)


def decide_action(inputs: ActionInputs) -> ActionDecision:
    """Return the canonical action artifact for one deterministic evaluation."""

    evaluation = evaluate_action(inputs)
    safe = evaluation.safe_headroom
    pilot = (
        None
        if evaluation.pilot_range is None
        else PilotReference.model_validate(
            {
                "lower": evaluation.pilot_range.lower,
                "upper": evaluation.pilot_range.upper,
                "unit": inputs.unit,
                "rounding_mode": "down_to_measurement_resolution",
                "screening_only": True,
            }
        )
    )
    _assert_state_pilot_invariant(evaluation.state, pilot)

    return ActionDecision.model_validate(
        {
            "schema_version": "1.0.0",
            "run_id": inputs.run_id,
            "contract_id": inputs.contract_id,
            "state": evaluation.state,
            "reason_codes": tuple(code.value for code in evaluation.reason_codes),
            "safe_headroom": SafeHeadroom.model_validate(
                {
                    "value": safe.value,
                    "unit": inputs.unit,
                    "basis": safe.basis,
                    "eligible_protocol_ids": safe.eligible_protocol_ids,
                }
            ),
            "pilot_reference": pilot,
            "gates": ActionGates.model_validate(
                {
                    "contract_valid": inputs.contract_valid,
                    "evidence_sufficient": inputs.sufficiency.action_supported,
                    "ordered_stability": OrderedStability(inputs.stability.state.value),
                    "zero_headroom_block": evaluation.zero_headroom_block,
                }
            ),
            "conflict": evaluation.conflict,
            "evidence_ids": inputs.evidence_ids,
            "claim_boundary": _claim_boundary(),
        }
    )


def _construct_pilot_range(
    *,
    state: ActionState,
    safe_headroom: float | None,
    minimum_actionable_shift: float,
    maximum_screening_shift: float,
    measurement_resolution: float | None,
) -> tuple[PilotRange | None, ActionReasonCode | None]:
    if safe_headroom is None or not math.isfinite(safe_headroom):
        return None, ActionReasonCode.NO_ELIGIBLE_HEADROOM
    if measurement_resolution is None:
        return None, ActionReasonCode.MEASUREMENT_RESOLUTION_UNAVAILABLE

    safe_decimal = _decimal(safe_headroom)
    minimum = _decimal(minimum_actionable_shift)
    maximum = _decimal(maximum_screening_shift)
    resolution = _decimal(measurement_resolution)

    if state is ActionState.PILOT_RANGE_SUPPORTED:
        raw_lower = max(minimum, Decimal("0.30") * safe_decimal)
        raw_upper = min(maximum, Decimal("0.80") * safe_decimal)
    elif state is ActionState.PILOT_ONLY_CONSERVATIVE:
        raw_lower = minimum
        raw_upper = min(maximum, Decimal("0.50") * safe_decimal)
    else:  # defensive: callers may not construct pilot ranges for blocked states
        raise ValueError("pilot ranges are only defined for pilot states")

    lower = _floor_to_resolution(raw_lower, resolution)
    upper = _floor_to_resolution(raw_upper, resolution)
    if upper <= 0:
        return None, ActionReasonCode.PILOT_RANGE_NONPOSITIVE
    if lower < minimum or upper < minimum:
        return None, ActionReasonCode.PILOT_RANGE_SUBMINIMUM
    if upper < lower:
        return None, ActionReasonCode.PILOT_RANGE_INVERTED
    return PilotRange(lower=float(lower), upper=float(upper)), None


def _summarize_conflict(
    inputs: ActionInputs,
    safe: SafeHeadroomSummary,
    parametric_warning: bool,
) -> tuple[ProtocolConflict, tuple[ActionReasonCode, ...]]:
    values = tuple(value for _, value in safe.conservative_values)
    spread = max(values) - min(values) if len(values) >= 2 else None
    spread_material = spread is not None and spread > inputs.protocol_spread_tolerance
    material = spread_material or inputs.material_state_or_assumption_conflict or parametric_warning
    reasons: list[ActionReasonCode] = []
    if spread_material:
        reasons.append(ActionReasonCode.PROTOCOL_SPREAD_MATERIAL)
    if inputs.material_state_or_assumption_conflict:
        reasons.append(ActionReasonCode.PROTOCOL_STATE_OR_ASSUMPTION_CONFLICT)
    if inputs.near_tie:
        reasons.append(ActionReasonCode.RIEC_NEAR_TIE)
    if parametric_warning:
        reasons.append(ActionReasonCode.PARAMETRIC_DIAGNOSTIC_MATERIAL)
    return (
        ProtocolConflict.model_validate(
            {
                "material_protocol_conflict": material,
                "near_tie": inputs.near_tie,
                "protocol_spread": spread,
                "spread_tolerance": inputs.protocol_spread_tolerance,
            }
        ),
        tuple(reasons),
    )


def _valid_bootstrap_lower_bound(
    bootstrap: BootstrapSummary | None,
    protocol_id: ProtocolId,
) -> float | None:
    if bootstrap is None or not bootstrap.valid:
        return None
    for candidate_id, value in bootstrap.lower_bounds:
        if candidate_id == protocol_id and math.isfinite(value):
            return value
    return None


def _has_material_parametric_warning(
    results: tuple[ProtocolComputation, ...],
) -> bool:
    return any(
        result.protocol_id in _PARAMETRIC_PROTOCOLS and result.material_warning
        for result in results
    )


def _validate_summary_provenance(inputs: ActionInputs) -> None:
    stability = inputs.stability
    stability_computation = stability.computation
    if (
        stability_computation.protocol_id is not ProtocolId.G1_ORDERED_STABILITY_SCREEN
        or stability_computation.role is not ProtocolRole.STABILITY_GATE
    ):
        raise ValueError("stability summary must wrap the frozen G1 computation")
    expected_stability_statuses = {
        G1Status.PASS: {ProtocolStatus.OK, ProtocolStatus.WARNING},
        G1Status.MATERIAL_WARNING: {ProtocolStatus.WARNING},
        G1Status.INELIGIBLE: {ProtocolStatus.INELIGIBLE},
    }
    if stability_computation.status not in expected_stability_statuses[stability.state]:
        raise ValueError("G1 state and computation status are inconsistent")
    if (
        not math.isfinite(stability.ordered_coverage)
        or not 0.0 <= stability.ordered_coverage <= 1.0
    ):
        raise ValueError("G1 ordered coverage must be a finite fraction")

    sufficiency = inputs.sufficiency
    sufficiency_computation = sufficiency.computation
    if (
        sufficiency_computation.protocol_id is not ProtocolId.G2_EVIDENCE_SUFFICIENCY_GATE
        or sufficiency_computation.role is not ProtocolRole.EVIDENCE_GATE
    ):
        raise ValueError("sufficiency summary must wrap the frozen G2 computation")
    if sufficiency.action_supported and not sufficiency.exploratory_supported:
        raise ValueError("G2 action support requires exploratory support")
    expected_sufficiency_status = (
        ProtocolStatus.OK if sufficiency.action_supported else ProtocolStatus.INELIGIBLE
    )
    if sufficiency_computation.status is not expected_sufficiency_status:
        raise ValueError("G2 support and computation status are inconsistent")

    bootstrap = inputs.bootstrap
    if bootstrap is None:
        return
    if not isinstance(bootstrap, BootstrapSummary):
        raise ValueError("bootstrap must be a typed U1 summary")
    bootstrap_computation = bootstrap.computation
    if (
        bootstrap_computation.protocol_id is not ProtocolId.U1_GROUP_BOOTSTRAP_BOUND
        or bootstrap_computation.role is not ProtocolRole.UNCERTAINTY
        or not bootstrap_computation.uncertainty.conditional_on_selection
    ):
        raise ValueError("bootstrap summary must wrap conditional frozen U1 uncertainty")
    counts = (
        bootstrap.requested_replicates,
        bootstrap.successful_replicates,
        bootstrap.failed_replicates,
    )
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in counts):
        raise ValueError("U1 replicate counts must be nonnegative integers")
    lower_ids = tuple(protocol_id for protocol_id, _ in bootstrap.lower_bounds)
    if len(set(lower_ids)) != len(lower_ids) or any(
        protocol_id not in _HEADROOM_PROTOCOL_ORDER for protocol_id in lower_ids
    ):
        raise ValueError("U1 lower bounds must use unique frozen H1/H2/H3 IDs")
    if any(not math.isfinite(value) or value < 0.0 for _, value in bootstrap.lower_bounds):
        raise ValueError("U1 lower bounds must be finite and nonnegative")
    if bootstrap.valid:
        if (
            not bootstrap.lower_bounds
            or bootstrap.requested_replicates <= 0
            or bootstrap.successful_replicates <= 0
            or bootstrap.successful_replicates + bootstrap.failed_replicates
            != bootstrap.requested_replicates
        ):
            raise ValueError("valid U1 summary has inconsistent bounds or replicate counts")
    elif bootstrap.lower_bounds:
        raise ValueError("ineligible U1 summary must not expose lower bounds")


def _headroom_guard_reason(
    value: float | None,
    minimum_actionable_shift: float,
) -> ActionReasonCode | None:
    if value is None or not math.isfinite(value):
        return ActionReasonCode.NO_ELIGIBLE_HEADROOM
    if value <= 0:
        return ActionReasonCode.HEADROOM_NONPOSITIVE
    if value < minimum_actionable_shift:
        return ActionReasonCode.HEADROOM_BELOW_MINIMUM_ACTIONABLE
    return None


def _floor_to_resolution(value: Decimal, resolution: Decimal) -> Decimal:
    if resolution <= 0:
        raise ValueError("measurement_resolution must be positive")
    steps = (value / resolution).to_integral_value(rounding=ROUND_FLOOR)
    return steps * resolution


def _decimal(value: float) -> Decimal:
    try:
        result = Decimal(str(value))
    except InvalidOperation as exc:  # pragma: no cover - guarded by input validation
        raise ValueError("policy inputs must be finite decimals") from exc
    if not result.is_finite():
        raise ValueError("policy inputs must be finite decimals")
    return result


def _evaluation(
    state: ActionState,
    reasons: tuple[ActionReasonCode, ...],
    safe: SafeHeadroomSummary,
    pilot_range: PilotRange | None,
    conflict: ProtocolConflict,
    zero_headroom_block: bool,
) -> ActionEvaluation:
    if not reasons:
        raise AssertionError("every action state requires a reason code")
    return ActionEvaluation(
        state=state,
        reason_codes=_ordered_unique_reasons(reasons),
        safe_headroom=safe,
        pilot_range=pilot_range,
        conflict=conflict,
        zero_headroom_block=zero_headroom_block,
    )


def _ordered_unique_reasons(
    reasons: tuple[ActionReasonCode, ...],
) -> tuple[ActionReasonCode, ...]:
    present = set(reasons)
    return tuple(code for code in ActionReasonCode if code in present)


def _claim_boundary() -> ClaimBoundary:
    return ClaimBoundary.model_validate(
        {
            "allowed": (
                "Describe the deterministic protocol estimates and evidence conflicts.",
                "Describe a pilot range only as a retrospective screening reference.",
            ),
            "conditional": (
                "A retrospective screening reference is conditional on the confirmed policy "
                "and requires controlled pilot validation and engineering review.",
            ),
            "prohibited": (
                "Do not claim achieved savings, regulatory compliance, an optimal or safe "
                "production setpoint, successful live deployment, causal improvement, or zero "
                "underfill risk.",
            ),
        }
    )


def _assert_state_pilot_invariant(
    state: ActionState,
    pilot: PilotReference | None,
) -> None:
    pilot_state = state in {
        ActionState.PILOT_ONLY_CONSERVATIVE,
        ActionState.PILOT_RANGE_SUPPORTED,
    }
    if pilot_state != (pilot is not None):
        raise AssertionError("pilot_reference must exist exactly for the two pilot states")


def _require_finite_nonnegative(value: float, name: str) -> None:
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"{name} must be finite and nonnegative")


def _require_finite_positive(value: float, name: str) -> None:
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be finite and positive")


__all__ = [
    "ActionEvaluation",
    "ActionInputs",
    "ActionReasonCode",
    "PilotRange",
    "SafeHeadroomSummary",
    "decide_action",
    "evaluate_action",
    "summarize_safe_headroom",
]
