"""Confirmed-order stability screening; this is not certified SPC."""

from __future__ import annotations

import math
import statistics
from collections import defaultdict
from collections.abc import Sequence

from riec_guard.contract.models import (
    ProtocolId,
    ProtocolRole,
    ProtocolStatus,
    WarningSeverity,
)
from riec_guard.protocols.models import (
    G1Status,
    Metric,
    ProtocolComputation,
    ProtocolReasonCode,
    StabilitySummary,
    Uncertainty,
    Warning,
)

_MR_D2 = 1.128


def run_ordered_stability_screen(
    quantities: Sequence[float],
    products: Sequence[str],
    streams: Sequence[str],
    times: Sequence[float],
    tie_break_keys: Sequence[tuple[str, ...]],
    *,
    order_confirmed: bool,
    stream_confirmed: bool,
    min_points_per_stream: int,
    minimum_coverage: float,
) -> StabilitySummary:
    """Apply the four frozen P0 rules within validated product/stream order."""

    _validate_thresholds(min_points_per_stream, minimum_coverage)
    n_rows = len(quantities)
    if not order_confirmed:
        return _ineligible(
            n_rows=n_rows,
            min_points_per_stream=min_points_per_stream,
            minimum_coverage=minimum_coverage,
            code=ProtocolReasonCode.ORDER_UNCONFIRMED,
            message="Ordered stability screening requires explicitly confirmed time order.",
        )
    if not stream_confirmed:
        return _ineligible(
            n_rows=n_rows,
            min_points_per_stream=min_points_per_stream,
            minimum_coverage=minimum_coverage,
            code=ProtocolReasonCode.ORDER_STREAM_UNAVAILABLE,
            message="Ordered stability screening requires an explicitly confirmed stream field.",
        )

    _validate_rows(quantities, products, streams, times, tie_break_keys)
    grouped: dict[tuple[str, str], list[int]] = defaultdict(list)
    for index, pair in enumerate(zip(products, streams, strict=True)):
        grouped[pair].append(index)

    eligible_sequences: list[tuple[float, ...]] = []
    unresolved_tie_rows = 0
    eligible_rows = 0
    eligible_streams = 0
    for indices in grouped.values():
        sequences, tied_rows = _ordered_supported_sequences(
            indices,
            quantities=quantities,
            times=times,
            tie_break_keys=tie_break_keys,
            min_points_per_stream=min_points_per_stream,
        )
        unresolved_tie_rows += tied_rows
        if sequences:
            eligible_streams += 1
            eligible_sequences.extend(sequences)
            eligible_rows += sum(len(sequence) for sequence in sequences)

    coverage = eligible_rows / n_rows if n_rows else 0.0
    warnings: list[Warning] = []
    if unresolved_tie_rows:
        warnings.append(
            Warning(
                code=ProtocolReasonCode.ORDER_TIE_UNRESOLVED,
                severity=WarningSeverity.WARNING,
                message="Rows in unresolved tied-order segments were excluded from screening.",
            )
        )
    if coverage < minimum_coverage:
        warnings.append(
            Warning(
                code=ProtocolReasonCode.ORDERED_COVERAGE_INSUFFICIENT,
                severity=WarningSeverity.BLOCKING,
                message="Eligible ordered-stream coverage is below the configured minimum.",
            )
        )
        return _build_summary(
            state=G1Status.INELIGIBLE,
            status=ProtocolStatus.INELIGIBLE,
            n_rows=n_rows,
            total_streams=len(grouped),
            eligible_streams=eligible_streams,
            eligible_rows=eligible_rows,
            coverage=coverage,
            min_points_per_stream=min_points_per_stream,
            minimum_coverage=minimum_coverage,
            rule_counts=(0, 0, 0, 0),
            warnings=tuple(warnings),
        )

    counts = [0, 0, 0, 0]
    fallback_count = 0
    for values in eligible_sequences:
        sequence_counts, used_fallback = _screen_sequence(values)
        for index, count in enumerate(sequence_counts):
            counts[index] += count
        fallback_count += int(used_fallback)

    if fallback_count:
        warnings.append(
            Warning(
                code=ProtocolReasonCode.MR_SCALE_FALLBACK,
                severity=WarningSeverity.WARNING,
                message="A degenerate moving-range scale used the declared sample-SD fallback.",
            )
        )
    rule_definitions = (
        (
            ProtocolReasonCode.STABILITY_POINT_BEYOND_3SIGMA,
            "At least one point exceeded the stream mean by more than three MR sigma.",
        ),
        (
            ProtocolReasonCode.STABILITY_EIGHT_ONE_SIDE,
            "At least eight consecutive points were strictly on one side of the stream mean.",
        ),
        (
            ProtocolReasonCode.STABILITY_SIX_MONOTONE,
            "At least six consecutive points were strictly monotone.",
        ),
        (
            ProtocolReasonCode.STABILITY_QUARTILE_SHIFT,
            "The early-to-late quartile mean shift exceeded 1.5 within-stream SD.",
        ),
    )
    for count, (code, message) in zip(counts, rule_definitions, strict=True):
        if count:
            warnings.append(Warning(code=code, severity=WarningSeverity.MATERIAL, message=message))

    material = any(counts)
    status = ProtocolStatus.WARNING if warnings else ProtocolStatus.OK
    return _build_summary(
        state=G1Status.MATERIAL_WARNING if material else G1Status.PASS,
        status=status,
        n_rows=n_rows,
        total_streams=len(grouped),
        eligible_streams=eligible_streams,
        eligible_rows=eligible_rows,
        coverage=coverage,
        min_points_per_stream=min_points_per_stream,
        minimum_coverage=minimum_coverage,
        rule_counts=(counts[0], counts[1], counts[2], counts[3]),
        warnings=tuple(warnings),
    )


def _ordered_supported_sequences(
    indices: Sequence[int],
    *,
    quantities: Sequence[float],
    times: Sequence[float],
    tie_break_keys: Sequence[tuple[str, ...]],
    min_points_per_stream: int,
) -> tuple[tuple[tuple[float, ...], ...], int]:
    by_time: dict[float, list[int]] = defaultdict(list)
    for index in indices:
        by_time[float(times[index])].append(index)

    segments: list[list[int]] = [[]]
    unresolved_rows = 0
    for time_value in sorted(by_time):
        tied = by_time[time_value]
        if len(tied) > 1:
            keys = [tie_break_keys[index] for index in tied]
            deterministic = all(key and all(part for part in key) for key in keys) and len(
                set(keys)
            ) == len(keys)
            if not deterministic:
                unresolved_rows += len(tied)
                if segments[-1]:
                    segments.append([])
                continue
            tied.sort(key=lambda index: tie_break_keys[index])
        segments[-1].extend(tied)

    eligible = tuple(
        tuple(float(quantities[index]) for index in segment)
        for segment in segments
        if len(segment) >= min_points_per_stream
    )
    return eligible, unresolved_rows


def _screen_sequence(values: tuple[float, ...]) -> tuple[tuple[int, int, int, int], bool]:
    mean = statistics.fmean(values)
    moving_ranges = tuple(abs(right - left) for left, right in zip(values, values[1:]))
    mr_sigma = statistics.fmean(moving_ranges) / _MR_D2 if moving_ranges else 0.0
    sample_sd = statistics.stdev(values) if len(values) > 1 else 0.0
    fallback = not math.isfinite(mr_sigma) or mr_sigma <= 0.0
    sigma = sample_sd if fallback else mr_sigma

    beyond = sum(1 for value in values if sigma > 0.0 and abs(value - mean) > 3.0 * sigma)
    one_side = _one_side_runs(values, mean, length=8)
    monotone = _monotone_runs(values, length=6)
    quartile_count = max(1, len(values) // 4)
    early_mean = statistics.fmean(values[:quartile_count])
    late_mean = statistics.fmean(values[-quartile_count:])
    quartile_shift = int(sample_sd > 0.0 and abs(early_mean - late_mean) > 1.5 * sample_sd)
    return (beyond, one_side, monotone, quartile_shift), fallback


def _one_side_runs(values: Sequence[float], mean: float, *, length: int) -> int:
    hits = 0
    direction = 0
    run = 0
    for value in values:
        next_direction = 1 if value > mean else -1 if value < mean else 0
        if next_direction == 0:
            direction = 0
            run = 0
            continue
        run = run + 1 if next_direction == direction else 1
        direction = next_direction
        if run == length:
            hits += 1
    return hits


def _monotone_runs(values: Sequence[float], *, length: int) -> int:
    hits = 0
    direction = 0
    comparisons = 0
    for left, right in zip(values, values[1:]):
        next_direction = 1 if right > left else -1 if right < left else 0
        if next_direction == 0:
            direction = 0
            comparisons = 0
            continue
        comparisons = comparisons + 1 if next_direction == direction else 1
        direction = next_direction
        if comparisons == length - 1:
            hits += 1
    return hits


def _ineligible(
    *,
    n_rows: int,
    min_points_per_stream: int,
    minimum_coverage: float,
    code: ProtocolReasonCode,
    message: str,
) -> StabilitySummary:
    return _build_summary(
        state=G1Status.INELIGIBLE,
        status=ProtocolStatus.INELIGIBLE,
        n_rows=n_rows,
        total_streams=0,
        eligible_streams=0,
        eligible_rows=0,
        coverage=0.0,
        min_points_per_stream=min_points_per_stream,
        minimum_coverage=minimum_coverage,
        rule_counts=(0, 0, 0, 0),
        warnings=(Warning(code=code, severity=WarningSeverity.BLOCKING, message=message),),
    )


def _build_summary(
    *,
    state: G1Status,
    status: ProtocolStatus,
    n_rows: int,
    total_streams: int,
    eligible_streams: int,
    eligible_rows: int,
    coverage: float,
    min_points_per_stream: int,
    minimum_coverage: float,
    rule_counts: tuple[int, int, int, int],
    warnings: tuple[Warning, ...],
) -> StabilitySummary:
    point_count, one_side_count, monotone_count, quartile_count = rule_counts
    computation = ProtocolComputation(
        protocol_id=ProtocolId.G1_ORDERED_STABILITY_SCREEN,
        role=ProtocolRole.STABILITY_GATE,
        status=status,
        point_estimate=None,
        unit=None,
        uncertainty=Uncertainty.none(),
        metrics=(
            Metric("screening_only", True),
            Metric("n_rows", n_rows),
            Metric("total_product_streams", total_streams),
            Metric("eligible_product_streams", eligible_streams),
            Metric("eligible_ordered_rows", eligible_rows),
            Metric("ordered_coverage", coverage),
            Metric("min_points_per_stream", min_points_per_stream),
            Metric("minimum_ordered_coverage", minimum_coverage),
            Metric("point_beyond_3sigma_count", point_count),
            Metric("eight_one_side_run_count", one_side_count),
            Metric("six_monotone_run_count", monotone_count),
            Metric("quartile_shift_count", quartile_count),
        ),
        warnings=warnings,
        algorithm_notes=(
            "Screening only, not certified SPC. Product/stream sequences were sorted by "
            "confirmed time and deterministic tie-break keys; moving ranges never cross streams."
        ),
    )
    return StabilitySummary(computation=computation, state=state, ordered_coverage=coverage)


def _validate_thresholds(min_points_per_stream: int, minimum_coverage: float) -> None:
    if isinstance(min_points_per_stream, bool) or min_points_per_stream < 3:
        raise ValueError("min_points_per_stream must be at least three")
    if not math.isfinite(minimum_coverage) or not 0.0 <= minimum_coverage <= 1.0:
        raise ValueError("minimum_coverage must be between zero and one")


def _validate_rows(
    quantities: Sequence[float],
    products: Sequence[str],
    streams: Sequence[str],
    times: Sequence[float],
    tie_break_keys: Sequence[tuple[str, ...]],
) -> None:
    lengths = {len(quantities), len(products), len(streams), len(times), len(tie_break_keys)}
    if len(lengths) != 1:
        raise ValueError("ordered stability inputs must have equal lengths")
    if not quantities:
        raise ValueError("ordered stability inputs must not be empty")
    if any(isinstance(value, bool) or not math.isfinite(float(value)) for value in quantities):
        raise ValueError("quantities must be finite numbers")
    if any(not product or not stream for product, stream in zip(products, streams, strict=True)):
        raise ValueError("product and stream values must be non-empty")
    if any(isinstance(value, bool) or not math.isfinite(float(value)) for value in times):
        raise ValueError("times must be finite numbers")


__all__ = ["run_ordered_stability_screen"]
