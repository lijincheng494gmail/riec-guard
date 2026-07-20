from __future__ import annotations

from riec_guard.contract.models import ProtocolId, ProtocolStatus, UncertaintyKind
from riec_guard.protocols.group_bootstrap import run_group_bootstrap
from riec_guard.protocols.models import ProtocolReasonCode
from riec_guard.riec.design import PreparedDataset, SemanticSeries


def _dataset(group_count: int = 8) -> PreparedDataset:
    response = tuple(
        value
        for group_index in range(group_count)
        for value in (float(group_index), float(group_index) + 0.25)
    )
    tokens = tuple(f"GRP-{group_index}" for group_index in range(group_count) for _ in range(2))
    keys = tuple((token,) for token in tokens)
    n_rows = len(response)
    return PreparedDataset(
        response=response,
        group_keys=keys,
        group_tokens=tokens,
        product=SemanticSeries("product", "product", True, tuple("P" for _ in response)),
        stream=SemanticSeries("stream", "stream", True, tuple("S" for _ in response)),
        shift=SemanticSeries("shift", None, False, None),
        time_hours=tuple(float(index) for index in range(n_rows)),
        time_column="time",
        time_confirmed=True,
        row_order=tuple(range(n_rows)),
        n_rows=n_rows,
        n_groups=group_count,
    )


def _mean_evaluator(dataset: PreparedDataset) -> dict[ProtocolId, float]:
    return {
        ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE: sum(dataset.response) / dataset.n_rows,
        ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL: min(dataset.response) + 0.5,
    }


def test_bootstrap_is_seeded_conditional_and_reproducible() -> None:
    kwargs = {
        "protocol_ids": (
            ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE,
            ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL,
        ),
        "replicate_evaluator": _mean_evaluator,
        "replicates": 20,
        "seed": 20260718,
        "confidence": 0.9,
        "min_groups": 8,
        "min_success": 20,
        "max_failed_fraction": 0.0,
        "unit": "mL",
    }
    first = run_group_bootstrap(_dataset(), **kwargs)  # type: ignore[arg-type]
    second = run_group_bootstrap(_dataset(), **kwargs)  # type: ignore[arg-type]

    assert first == second
    assert first.valid
    assert first.computation.status is ProtocolStatus.OK
    assert first.computation.uncertainty.kind is UncertaintyKind.ONE_SIDED_LOWER
    assert first.computation.uncertainty.level == 0.9
    assert first.computation.uncertainty.conditional_on_selection
    assert first.successful_replicates == 20
    assert first.failed_replicates == 0
    assert first.lower_bound(ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE) is not None
    assert first.lower_bound(ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL) is not None
    assert first.computation.point_estimate == min(value for _, value in first.lower_bounds)


def test_insufficient_success_blocks_bootstrap_bound() -> None:
    def invalid_evaluator(_: PreparedDataset) -> dict[ProtocolId, float]:
        return {}

    result = run_group_bootstrap(
        _dataset(),
        protocol_ids=(ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE,),
        replicate_evaluator=invalid_evaluator,
        replicates=6,
        min_success=5,
        max_failed_fraction=0.1,
        unit="mL",
    )

    assert not result.valid
    assert result.computation.status is ProtocolStatus.INELIGIBLE
    assert result.computation.point_estimate is None
    assert result.lower_bounds == ()
    assert result.successful_replicates == 0
    assert result.failed_replicates == 6
    warning_codes = {warning.code for warning in result.computation.warnings}
    assert ProtocolReasonCode.BOOTSTRAP_INSUFFICIENT_SUCCESS in warning_codes
    assert ProtocolReasonCode.BOOTSTRAP_FAILURE_FRACTION in warning_codes


def test_fewer_than_eight_groups_is_ineligible_by_default() -> None:
    result = run_group_bootstrap(
        _dataset(group_count=7),
        protocol_ids=(ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE,),
        replicate_evaluator=_mean_evaluator,
        replicates=4,
        min_success=4,
        unit="mL",
    )

    assert not result.valid
    assert result.computation.warnings[0].code is ProtocolReasonCode.BOOTSTRAP_INSUFFICIENT_GROUPS


def test_nondefault_confidence_uses_exact_inverse_empirical_cdf_rank() -> None:
    counter = 0

    def ordered_evaluator(_: PreparedDataset) -> dict[ProtocolId, float]:
        nonlocal counter
        counter += 1
        return {ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE: float(counter)}

    result = run_group_bootstrap(
        _dataset(),
        protocol_ids=(ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE,),
        replicate_evaluator=ordered_evaluator,
        replicates=20,
        confidence=0.85,
        min_success=20,
        max_failed_fraction=0.0,
        unit="mL",
    )

    assert result.lower_bound(ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE) == 3.0
    assert result.computation.metric("lower_quantile_probability") == 0.15


def test_exact_ten_percent_failure_boundary_remains_valid() -> None:
    counter = 0

    def boundary_evaluator(_: PreparedDataset) -> dict[ProtocolId, float]:
        nonlocal counter
        counter += 1
        if counter <= 2:
            raise ValueError("bounded fixture failure")
        return {ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE: float(counter)}

    result = run_group_bootstrap(
        _dataset(),
        protocol_ids=(ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE,),
        replicate_evaluator=boundary_evaluator,
        replicates=20,
        min_success=18,
        max_failed_fraction=0.1,
        unit="mL",
    )

    assert result.valid
    assert result.successful_replicates == 18
    assert result.failed_replicates == 2
    assert result.computation.status is ProtocolStatus.WARNING
