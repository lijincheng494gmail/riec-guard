"""Deterministic generators for the three public Macro-03 demonstration worlds."""

from __future__ import annotations

import csv
import hashlib
import io
import math
from datetime import datetime, timedelta, timezone

import numpy as np
import numpy.typing as npt

from riec_guard.benchmarks.models import (
    DemoG1State,
    GeneratedScenario,
    MechanismParameter,
    PublicClassification,
    SCENARIO_ORDER,
    ScenarioDefinition,
    ScenarioExpectation,
    ScenarioId,
    SharedPolicyProfile,
    SharedScenarioDesign,
)
from riec_guard.contract.models import ActionState

_SCENARIO_VERSION = "1.0.0"
_STARTED_AT = datetime(2026, 7, 18, tzinfo=timezone.utc)
_HEADER = (
    "quantity",
    "product",
    "batch_id",
    "timestamp",
    "stream",
    "shift",
    "row_sequence",
)
_PRODUCTS = ("product_A", "product_B")
_STREAMS = ("stream_1", "stream_2")
_SHIFTS = ("day", "night")
_PRODUCT_EFFECT = {"product_A": -0.04, "product_B": 0.04}
_STREAM_EFFECT = {"stream_1": -0.03, "stream_2": 0.03}

_SHARED_DESIGN = SharedScenarioDesign.model_validate(
    {
        "deployment_group_count": 12,
        "product_count": 2,
        "stream_count": 2,
        "shift_count": 2,
        "replicates_per_cell": 11,
        "rows_per_group": 88,
        "row_count": 1056,
        "rows_per_product": 528,
        "expected_tail_count_per_product": 5.28,
    }
)

_SHARED_POLICY = SharedPolicyProfile.model_validate(
    {
        "profile_id": "public-demo-policy.v1",
        "nominal_quantity": 250.0,
        "lower_limit": 249.5,
        "alpha": 0.01,
        "measurement_resolution": 0.01,
        "minimum_actionable_shift": 0.05,
        "maximum_screening_shift": 0.5,
        "protocol_spread_tolerance": 0.5,
        "unit": "mL",
        "min_expected_tail_count": 5,
        "bootstrap_replicates": 200,
        "bootstrap_seed": 20260718,
    }
)


def _parameter(name: str, value: float, unit: str | None = None) -> MechanismParameter:
    return MechanismParameter.model_validate({"name": name, "value": value, "unit": unit})


_SCENARIOS = (
    ScenarioDefinition.model_validate(
        {
            "scenario_id": ScenarioId.STABLE_SYMMETRIC,
            "scenario_version": _SCENARIO_VERSION,
            "display_name": "Stable symmetric process",
            "mechanism_description": (
                "Balanced additive product, stream, and shift effects with bounded, symmetric, "
                "near-Gaussian process noise and no deployment-group drift."
            ),
            "domain_hint": "Public packaged-volume demonstration",
            "seed": 20260731,
            "csv_asset": "data/public_synthetic/stable_symmetric.csv",
            "classification": PublicClassification.PUBLIC_SYNTHETIC,
            "design": _SHARED_DESIGN,
            "policy": _SHARED_POLICY,
            "mechanism_parameters": (
                _parameter("base_quantity", 250.25, "mL"),
                _parameter("product_effect_magnitude", 0.04, "mL"),
                _parameter("stream_effect_magnitude", 0.03, "mL"),
                _parameter("shift_effect_magnitude", 0.06, "mL"),
                _parameter("primary_noise_scale", 0.012, "mL"),
                _parameter("wide_noise_scale", 0.024, "mL"),
                _parameter("wide_component_count_per_group", 6.0, "count"),
                _parameter("noise_clip", 0.045, "mL"),
            ),
            "expectation": ScenarioExpectation.model_validate(
                {
                    "g1_state": DemoG1State.PASS,
                    "g2_action_supported": True,
                    "protocol_conflict": False,
                    "action_state": ActionState.PILOT_RANGE_SUPPORTED,
                    "positive_pilot_interval": True,
                    "h2_more_optimistic_than_h1_or_h3": False,
                }
            ),
            "limitation": (
                "Illustrative public synthetic data only; the scenario is not evidence of "
                "performance, savings, or suitability in an operating process."
            ),
        }
    ),
    ScenarioDefinition.model_validate(
        {
            "scenario_id": ScenarioId.HEAVY_TAIL_PARTICULATE,
            "scenario_version": _SCENARIO_VERSION,
            "display_name": "Heavy-tail particulate variation",
            "mechanism_description": (
                "Stable additive group structure with bounded central noise and one bounded "
                "low-side particulate-like shock in every deployment group."
            ),
            "domain_hint": "Public packaged-volume demonstration",
            "seed": 20260801,
            "csv_asset": "data/public_synthetic/heavy_tail_particulate.csv",
            "classification": PublicClassification.PUBLIC_SYNTHETIC,
            "design": _SHARED_DESIGN,
            "policy": _SHARED_POLICY,
            "mechanism_parameters": (
                _parameter("base_quantity", 250.25, "mL"),
                _parameter("product_effect_magnitude", 0.04, "mL"),
                _parameter("stream_effect_magnitude", 0.03, "mL"),
                _parameter("shift_effect_magnitude", 0.10, "mL"),
                _parameter("central_noise_scale", 0.012, "mL"),
                _parameter("central_noise_clip", 0.03, "mL"),
                _parameter("low_side_shock", -0.30, "mL"),
                _parameter("shocks_per_group", 1.0, "count"),
            ),
            "expectation": ScenarioExpectation.model_validate(
                {
                    "g1_state": DemoG1State.PASS,
                    "g2_action_supported": True,
                    "protocol_conflict": True,
                    "action_state": ActionState.PILOT_ONLY_CONSERVATIVE,
                    "positive_pilot_interval": True,
                    "h2_more_optimistic_than_h1_or_h3": True,
                }
            ),
            "limitation": (
                "The bounded shocks are a transparent synthetic mechanism, not a calibrated "
                "model of any material, package, line, or operating process."
            ),
        }
    ),
    ScenarioDefinition.model_validate(
        {
            "scenario_id": ScenarioId.BATCH_DRIFT_CHANGE_POINT,
            "scenario_version": _SCENARIO_VERSION,
            "display_name": "Ordered deployment-group drift",
            "mechanism_description": (
                "A deterministic bounded downward deployment-group trend is superimposed on "
                "small symmetric noise and stable product, stream, and shift effects."
            ),
            "domain_hint": "Public packaged-volume demonstration",
            "seed": 20260802,
            "csv_asset": "data/public_synthetic/batch_drift_change_point.csv",
            "classification": PublicClassification.PUBLIC_SYNTHETIC,
            "design": _SHARED_DESIGN,
            "policy": _SHARED_POLICY,
            "mechanism_parameters": (
                _parameter("base_quantity", 250.42, "mL"),
                _parameter("product_effect_magnitude", 0.04, "mL"),
                _parameter("stream_effect_magnitude", 0.03, "mL"),
                _parameter("shift_effect_magnitude", 0.05, "mL"),
                _parameter("initial_group_effect", 0.16, "mL"),
                _parameter("terminal_group_effect", -0.16, "mL"),
                _parameter("primary_noise_scale", 0.012, "mL"),
                _parameter("wide_noise_scale", 0.024, "mL"),
                _parameter("wide_noise_fraction", 0.08, "fraction"),
                _parameter("noise_clip", 0.045, "mL"),
            ),
            "expectation": ScenarioExpectation.model_validate(
                {
                    "g1_state": DemoG1State.MATERIAL_WARNING,
                    "g2_action_supported": True,
                    "protocol_conflict": True,
                    "action_state": ActionState.DIAGNOSE_PROCESS_FIRST,
                    "positive_pilot_interval": False,
                    "h2_more_optimistic_than_h1_or_h3": False,
                }
            ),
            "limitation": (
                "The ordered trend is intentionally visible for a screening demonstration; "
                "it is not certified process-control evidence or a causal diagnosis."
            ),
        }
    ),
)

if tuple(definition.scenario_id for definition in _SCENARIOS) != SCENARIO_ORDER:
    raise AssertionError("public scenario definitions must retain the frozen order")


def shared_design() -> SharedScenarioDesign:
    """Return the immutable geometry shared by every public scenario."""

    return _SHARED_DESIGN


def shared_policy() -> SharedPolicyProfile:
    """Return the immutable illustrative policy shared by every public scenario."""

    return _SHARED_POLICY


def scenario_definitions() -> tuple[ScenarioDefinition, ...]:
    """Return exactly the three frozen public definitions in canonical order."""

    return _SCENARIOS


def get_scenario_definition(scenario_id: ScenarioId | str) -> ScenarioDefinition:
    """Resolve only a frozen public scenario ID."""

    try:
        resolved = scenario_id if isinstance(scenario_id, ScenarioId) else ScenarioId(scenario_id)
    except (TypeError, ValueError):
        raise ValueError("scenario_id must identify one frozen public scenario") from None
    for definition in _SCENARIOS:
        if definition.scenario_id is resolved:
            return definition
    raise ValueError("scenario_id must identify one frozen public scenario")


def generate_scenario_csv(
    scenario_id: ScenarioId | str,
    seed_override: int | None = None,
) -> bytes:
    """Generate canonical UTF-8/LF CSV bytes without changing the frozen definition."""

    definition = get_scenario_definition(scenario_id)
    seed = definition.seed if seed_override is None else _validated_seed(seed_override)
    rng = np.random.default_rng(seed)
    rows = _generate_rows(definition.scenario_id, rng)
    if len(rows) != _SHARED_DESIGN.row_count:
        raise AssertionError("public scenario generator produced an invalid row count")

    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(_HEADER)
    writer.writerows(rows)
    encoded = output.getvalue().encode("utf-8")
    if not encoded.endswith(b"\n"):
        raise AssertionError("public scenario CSV must end with a line feed")
    return encoded


def generate_scenario(
    scenario_id: ScenarioId | str,
    seed_override: int | None = None,
) -> GeneratedScenario:
    """Generate one typed public scenario and bind its byte-level dataset identity."""

    definition = get_scenario_definition(scenario_id)
    csv_bytes = generate_scenario_csv(definition.scenario_id, seed_override=seed_override)
    return GeneratedScenario(
        definition=definition,
        csv_bytes=csv_bytes,
        dataset_sha256=hashlib.sha256(csv_bytes).hexdigest(),
    )


def _validated_seed(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**32 - 1:
        raise ValueError("seed_override must be an integer between zero and 2**32 - 1")
    return value


def _generate_rows(
    scenario_id: ScenarioId,
    rng: np.random.Generator,
) -> tuple[tuple[str, ...], ...]:
    rows: list[tuple[str, ...]] = []
    sequence = 0
    stable_noise = (
        _stable_bounded_noise(rng, _SHARED_DESIGN.rows_per_group)
        if scenario_id is ScenarioId.STABLE_SYMMETRIC
        else None
    )
    for group_index in range(_SHARED_DESIGN.deployment_group_count):
        if stable_noise is not None:
            # The agreement-control world repeats one bounded distribution across groups.
            # Whole-group resampling therefore tests stable support without a group-mixture
            # artifact, while the seeded template still changes when the scenario seed changes.
            symmetric_noise = stable_noise
        elif scenario_id is ScenarioId.BATCH_DRIFT_CHANGE_POINT:
            symmetric_noise = _symmetric_bounded_noise(rng, _SHARED_DESIGN.rows_per_group)
        else:
            symmetric_noise = None
        group_row_index = 0
        for replicate in range(_SHARED_DESIGN.replicates_per_cell):
            for product in _PRODUCTS:
                for stream in _STREAMS:
                    # Keeping shift innermost makes the two shift levels alternate inside
                    # each ordered product/stream sequence used by the frozen G1 screen.
                    for shift in _SHIFTS:
                        quantity = _quantity(
                            scenario_id,
                            rng,
                            group_index=group_index,
                            group_row_index=group_row_index,
                            replicate=replicate,
                            product=product,
                            stream=stream,
                            shift=shift,
                            symmetric_noise=symmetric_noise,
                        )
                        if not math.isfinite(quantity):
                            raise AssertionError("public scenario quantity must be finite")
                        timestamp = _STARTED_AT + timedelta(minutes=sequence)
                        rows.append(
                            (
                                f"{quantity:.2f}",
                                product,
                                f"batch_{group_index + 1:02d}",
                                timestamp.isoformat().replace("+00:00", "Z"),
                                stream,
                                shift,
                                str(sequence + 1),
                            )
                        )
                        sequence += 1
                        group_row_index += 1
    return tuple(rows)


def _symmetric_bounded_noise(
    rng: np.random.Generator,
    size: int,
) -> npt.NDArray[np.float64]:
    if size % 2:
        raise AssertionError("symmetric public noise requires an even group size")
    half = size // 2
    magnitudes = np.abs(rng.normal(size=half))
    scales = np.where(rng.random(half) < 0.08, 0.024, 0.012)
    magnitudes = np.clip(magnitudes * scales, 0.0, 0.045)
    values = np.concatenate((magnitudes, -magnitudes)).astype(np.float64, copy=False)
    rng.shuffle(values)
    return values


def _stable_bounded_noise(
    rng: np.random.Generator,
    size: int,
) -> npt.NDArray[np.float64]:
    """Create a symmetric bounded Gaussian scale mixture with nonmaterial kurtosis."""

    if size % 2:
        raise AssertionError("stable public noise requires an even group size")
    half = size // 2
    magnitudes = np.abs(rng.normal(size=half))
    wide_positions = rng.choice(half, size=6, replace=False)
    scales = np.full(half, 0.012)
    scales[wide_positions] = 0.024
    magnitudes = np.clip(magnitudes * scales, 0.0, 0.045)
    values = np.concatenate((magnitudes, -magnitudes)).astype(np.float64, copy=False)
    rng.shuffle(values)
    return values


def _quantity(
    scenario_id: ScenarioId,
    rng: np.random.Generator,
    *,
    group_index: int,
    group_row_index: int,
    replicate: int,
    product: str,
    stream: str,
    shift: str,
    symmetric_noise: npt.NDArray[np.float64] | None,
) -> float:
    product_effect = _PRODUCT_EFFECT[product]
    stream_effect = _STREAM_EFFECT[stream]

    if scenario_id is ScenarioId.STABLE_SYMMETRIC:
        assert symmetric_noise is not None
        shift_effect = -0.06 if shift == "day" else 0.06
        return (
            250.25
            + product_effect
            + stream_effect
            + shift_effect
            + float(symmetric_noise[group_row_index])
        )

    if scenario_id is ScenarioId.HEAVY_TAIL_PARTICULATE:
        shift_effect = -0.10 if shift == "day" else 0.10
        noise = float(np.clip(rng.normal(0.0, 0.012), -0.03, 0.03))
        is_low_shock = (
            product == "product_A"
            and stream == "stream_1"
            and shift == "day"
            and replicate == (3 * group_index + 1) % 11
        )
        if is_low_shock:
            noise -= 0.30
        return 250.25 + product_effect + stream_effect + shift_effect + noise

    if scenario_id is ScenarioId.BATCH_DRIFT_CHANGE_POINT:
        assert symmetric_noise is not None
        shift_effect = -0.05 if shift == "day" else 0.05
        group_effect = 0.16 - 0.32 * group_index / 11.0
        return (
            250.42
            + product_effect
            + stream_effect
            + shift_effect
            + group_effect
            + float(symmetric_noise[group_row_index])
        )

    raise AssertionError("unregistered public scenario reached generation")


__all__ = [
    "generate_scenario",
    "generate_scenario_csv",
    "get_scenario_definition",
    "scenario_definitions",
    "shared_design",
    "shared_policy",
]
