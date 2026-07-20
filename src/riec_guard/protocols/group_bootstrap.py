"""Whole-deployment-group bootstrap conditional on a frozen RIEC selection."""

from __future__ import annotations

import math
import random
from collections.abc import Callable, Mapping, Sequence
from decimal import Decimal, ROUND_CEILING

from riec_guard.contract.models import (
    ProtocolId,
    ProtocolRole,
    ProtocolStatus,
    UncertaintyKind,
    WarningSeverity,
)
from riec_guard.protocols.models import (
    BootstrapSummary,
    Metric,
    ProtocolComputation,
    ProtocolReasonCode,
    Uncertainty,
    Warning,
)
from riec_guard.riec.design import PreparedDataset, SemanticSeries

BootstrapEvaluator = Callable[[PreparedDataset], Mapping[ProtocolId, float]]

_HEADROOM_PROTOCOL_IDS = frozenset(
    {
        ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE,
        ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL,
        ProtocolId.H3_STUDENT_T_RESIDUAL_TAIL,
    }
)


def resample_whole_groups(
    dataset: PreparedDataset,
    sampled_group_tokens: Sequence[str],
    *,
    replicate_index: int,
) -> PreparedDataset:
    """Copy complete sampled groups and assign each draw a local group identity.

    The returned identifiers contain no source group label.  Repeated draws of a
    source group therefore remain distinguishable to grouped refits without
    exposing or accidentally merging their source identity.
    """

    if isinstance(replicate_index, bool) or replicate_index < 0:
        raise ValueError("replicate_index must be a non-negative integer")
    if not sampled_group_tokens:
        raise ValueError("sampled_group_tokens must not be empty")
    _validate_dataset(dataset)

    indices_by_group_id = {
        group_id: tuple(
            index for index in dataset.row_order if dataset.group_tokens[index] == group_id
        )
        for group_id in sorted(set(dataset.group_tokens))
    }
    if any(group_id not in indices_by_group_id for group_id in sampled_group_tokens):
        raise ValueError("sampled_group_tokens contains an unknown group token")

    source_indices: list[int] = []
    local_tokens: list[str] = []
    local_keys: list[tuple[str, ...]] = []
    for draw_index, source_token in enumerate(sampled_group_tokens):
        member_indices = indices_by_group_id[source_token]
        local_token = f"BGRP-{replicate_index:06d}-{draw_index:06d}"
        local_key = ("bootstrap", f"{replicate_index:06d}", f"{draw_index:06d}")
        source_indices.extend(member_indices)
        local_tokens.extend(local_token for _ in member_indices)
        local_keys.extend(local_key for _ in member_indices)

    selected = tuple(source_indices)
    return PreparedDataset(
        response=tuple(dataset.response[index] for index in selected),
        group_keys=tuple(local_keys),
        group_tokens=tuple(local_tokens),
        product=_resample_series(dataset.product, selected),
        stream=_resample_series(dataset.stream, selected),
        shift=_resample_series(dataset.shift, selected),
        time_hours=(
            None
            if dataset.time_hours is None
            else tuple(dataset.time_hours[index] for index in selected)
        ),
        time_column=dataset.time_column,
        time_confirmed=dataset.time_confirmed,
        row_order=tuple(range(len(selected))),
        n_rows=len(selected),
        n_groups=len(sampled_group_tokens),
    )


def run_group_bootstrap(
    dataset: PreparedDataset,
    *,
    protocol_ids: Sequence[ProtocolId],
    replicate_evaluator: BootstrapEvaluator,
    replicates: int = 200,
    seed: int = 20260718,
    confidence: float = 0.9,
    min_groups: int = 8,
    min_success: int = 100,
    max_failed_fraction: float = 0.1,
    unit: str,
) -> BootstrapSummary:
    """Return deterministic empirical lower bounds from whole-group replicates.

    ``replicate_evaluator`` must refit only the caller's already-frozen main
    equivalence set.  Candidate selection is intentionally absent from this API.
    A replicate succeeds only when every requested headroom protocol returns one
    finite, non-negative value.
    """

    requested_ids = tuple(protocol_ids)
    _validate_bootstrap_inputs(
        dataset=dataset,
        protocol_ids=requested_ids,
        replicates=replicates,
        seed=seed,
        confidence=confidence,
        min_groups=min_groups,
        min_success=min_success,
        max_failed_fraction=max_failed_fraction,
        unit=unit,
    )

    if dataset.n_groups < min_groups:
        warning = Warning(
            code=ProtocolReasonCode.BOOTSTRAP_INSUFFICIENT_GROUPS,
            severity=WarningSeverity.BLOCKING,
            message="Whole-group bootstrap requires more deployment groups.",
        )
        return _summary(
            status=ProtocolStatus.INELIGIBLE,
            unit=unit,
            confidence=confidence,
            seed=seed,
            replicates=replicates,
            successful=0,
            failed=0,
            lower_bounds=(),
            warnings=(warning,),
            failure_codes=(warning.code.value,),
        )

    source_tokens = tuple(sorted(set(dataset.group_tokens)))
    rng = random.Random(seed)
    values_by_protocol: dict[ProtocolId, list[float]] = {
        protocol_id: [] for protocol_id in requested_ids
    }
    failure_codes: list[str] = []

    for replicate_index in range(replicates):
        sampled = tuple(rng.choice(source_tokens) for _ in range(dataset.n_groups))
        replicate = resample_whole_groups(
            dataset,
            sampled,
            replicate_index=replicate_index,
        )
        try:
            evaluated = replicate_evaluator(replicate)
            replicate_values = _validated_replicate_values(evaluated, requested_ids)
        except Exception:  # noqa: BLE001 - a failed bounded replicate is recorded, not retried
            failure_codes.append("BOOTSTRAP_REPLICATE_FAILED")
            continue
        for protocol_id, value in replicate_values.items():
            values_by_protocol[protocol_id].append(value)

    successful = len(next(iter(values_by_protocol.values())))
    failed = replicates - successful
    failed_fraction = failed / replicates
    warnings: list[Warning] = []
    if successful < min_success:
        warnings.append(
            Warning(
                code=ProtocolReasonCode.BOOTSTRAP_INSUFFICIENT_SUCCESS,
                severity=WarningSeverity.BLOCKING,
                message="Too few whole-group bootstrap replicates completed successfully.",
            )
        )
    if failed_fraction > max_failed_fraction:
        warnings.append(
            Warning(
                code=ProtocolReasonCode.BOOTSTRAP_FAILURE_FRACTION,
                severity=WarningSeverity.BLOCKING,
                message="The whole-group bootstrap failure fraction exceeds its limit.",
            )
        )
    if warnings:
        return _summary(
            status=ProtocolStatus.INELIGIBLE,
            unit=unit,
            confidence=confidence,
            seed=seed,
            replicates=replicates,
            successful=successful,
            failed=failed,
            lower_bounds=(),
            warnings=tuple(warnings),
            failure_codes=tuple(failure_codes),
        )

    lower_probability = float(Decimal("1") - Decimal(str(confidence)))
    lower_bounds = tuple(
        (
            protocol_id,
            _empirical_lower_quantile(values_by_protocol[protocol_id], lower_probability),
        )
        for protocol_id in requested_ids
    )
    if failed:
        warnings.append(
            Warning(
                code=ProtocolReasonCode.BOOTSTRAP_FAILURE_FRACTION,
                severity=WarningSeverity.WARNING,
                message="Some whole-group bootstrap replicates failed within the allowed limit.",
            )
        )
    return _summary(
        status=ProtocolStatus.WARNING if warnings else ProtocolStatus.OK,
        unit=unit,
        confidence=confidence,
        seed=seed,
        replicates=replicates,
        successful=successful,
        failed=failed,
        lower_bounds=lower_bounds,
        warnings=tuple(warnings),
        failure_codes=tuple(failure_codes),
    )


def _validated_replicate_values(
    evaluated: Mapping[ProtocolId, float],
    requested_ids: tuple[ProtocolId, ...],
) -> dict[ProtocolId, float]:
    values: dict[ProtocolId, float] = {}
    for protocol_id in requested_ids:
        if protocol_id not in evaluated:
            raise ValueError("replicate evaluator omitted a requested protocol")
        raw = evaluated[protocol_id]
        if isinstance(raw, bool):
            raise ValueError("replicate evaluator returned a non-numeric value")
        value = float(raw)
        if not math.isfinite(value) or value < 0.0:
            raise ValueError("replicate evaluator returned an invalid headroom value")
        values[protocol_id] = value
    return values


def _empirical_lower_quantile(values: Sequence[float], probability: float) -> float:
    """Inverse empirical CDF, avoiding interpolation above the observed lower order statistic."""

    ordered = sorted(values)
    rank = int(
        (Decimal(str(probability)) * Decimal(len(ordered))).to_integral_value(
            rounding=ROUND_CEILING
        )
    )
    index = max(0, rank - 1)
    return ordered[index]


def _summary(
    *,
    status: ProtocolStatus,
    unit: str,
    confidence: float,
    seed: int,
    replicates: int,
    successful: int,
    failed: int,
    lower_bounds: tuple[tuple[ProtocolId, float], ...],
    warnings: tuple[Warning, ...],
    failure_codes: tuple[str, ...],
) -> BootstrapSummary:
    minimum_bound = min((value for _, value in lower_bounds), default=None)
    metrics = [
        Metric("requested_replicates", replicates),
        Metric("successful_replicates", successful),
        Metric("failed_replicates", failed),
        Metric("failed_fraction", failed / replicates),
        Metric("bootstrap_seed", seed),
        Metric("one_sided_confidence", confidence),
        Metric(
            "lower_quantile_probability",
            float(Decimal("1") - Decimal(str(confidence))),
        ),
        Metric("lower_quantile_method", "inverse_empirical_cdf"),
        Metric("replicate_failure_codes", ",".join(sorted(set(failure_codes)))),
        Metric("conditional_on_selection", True),
    ]
    metrics.extend(
        Metric(f"{protocol_id.value}_lower_bound", value, unit)
        for protocol_id, value in lower_bounds
    )
    computation = ProtocolComputation(
        protocol_id=ProtocolId.U1_GROUP_BOOTSTRAP_BOUND,
        role=ProtocolRole.UNCERTAINTY,
        status=status,
        point_estimate=minimum_bound,
        unit=unit,
        uncertainty=Uncertainty(
            kind=UncertaintyKind.ONE_SIDED_LOWER,
            level=confidence,
            lower=minimum_bound,
            upper=None,
            conditional_on_selection=True,
        ),
        metrics=tuple(metrics),
        warnings=warnings,
        algorithm_notes=(
            "Whole deployment groups were sampled with replacement. Repeated draws received "
            "replicate-local group IDs; inference is conditional on the frozen main selection."
        ),
    )
    return BootstrapSummary(
        computation=computation,
        lower_bounds=lower_bounds,
        requested_replicates=replicates,
        successful_replicates=successful,
        failed_replicates=failed,
        failure_codes=failure_codes,
    )


def _resample_series(series: SemanticSeries, indices: tuple[int, ...]) -> SemanticSeries:
    return SemanticSeries(
        semantic=series.semantic,
        column=series.column,
        confirmed=series.confirmed,
        values=None if series.values is None else tuple(series.values[index] for index in indices),
    )


def _validate_dataset(dataset: PreparedDataset) -> None:
    lengths = {
        len(dataset.response),
        len(dataset.group_keys),
        len(dataset.group_tokens),
        len(dataset.row_order),
    }
    if dataset.n_rows <= 0 or lengths != {dataset.n_rows}:
        raise ValueError("PreparedDataset row fields are inconsistent")
    if set(dataset.row_order) != set(range(dataset.n_rows)):
        raise ValueError("PreparedDataset row_order is invalid")
    if len(set(dataset.group_tokens)) != dataset.n_groups:
        raise ValueError("PreparedDataset group count is inconsistent")
    for series in (dataset.product, dataset.stream, dataset.shift):
        if series.values is not None and len(series.values) != dataset.n_rows:
            raise ValueError("PreparedDataset semantic fields are inconsistent")
    if dataset.time_hours is not None and len(dataset.time_hours) != dataset.n_rows:
        raise ValueError("PreparedDataset time field is inconsistent")


def _validate_bootstrap_inputs(
    *,
    dataset: PreparedDataset,
    protocol_ids: tuple[ProtocolId, ...],
    replicates: int,
    seed: int,
    confidence: float,
    min_groups: int,
    min_success: int,
    max_failed_fraction: float,
    unit: str,
) -> None:
    _validate_dataset(dataset)
    if (
        not protocol_ids
        or len(set(protocol_ids)) != len(protocol_ids)
        or any(protocol_id not in _HEADROOM_PROTOCOL_IDS for protocol_id in protocol_ids)
    ):
        raise ValueError("protocol_ids must be unique frozen headroom protocol IDs")
    if isinstance(replicates, bool) or replicates < 1:
        raise ValueError("replicates must be positive")
    if isinstance(seed, bool) or seed < 0:
        raise ValueError("seed must be non-negative")
    if not math.isfinite(confidence) or not 0.5 < confidence < 1.0:
        raise ValueError("confidence must be finite and between 0.5 and 1")
    if isinstance(min_groups, bool) or min_groups < 2:
        raise ValueError("min_groups must be at least two")
    if isinstance(min_success, bool) or min_success < 1:
        raise ValueError("min_success must be positive")
    if not math.isfinite(max_failed_fraction) or not 0.0 <= max_failed_fraction <= 1.0:
        raise ValueError("max_failed_fraction must be between zero and one")
    if not unit or len(unit) > 32:
        raise ValueError("unit must be a non-empty canonical unit")


__all__ = ["BootstrapEvaluator", "resample_whole_groups", "run_group_bootstrap"]
