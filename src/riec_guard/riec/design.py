from __future__ import annotations

import csv
import hashlib
import io
import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from riec_guard.contract.models import (
    AuditContract,
    CandidateDefinition,
    ConversionMethod,
    FormulaTerm,
)


class RiecReasonCode(StrEnum):
    RIEC_CONTRACT_NOT_PERMITTED = "RIEC_CONTRACT_NOT_PERMITTED"
    RIEC_REGISTRY_MISMATCH = "RIEC_REGISTRY_MISMATCH"
    RIEC_RUN_OWNERSHIP_MISMATCH = "RIEC_RUN_OWNERSHIP_MISMATCH"
    RIEC_SOURCE_NOT_FOUND = "RIEC_SOURCE_NOT_FOUND"
    RIEC_DATASET_MISMATCH = "RIEC_DATASET_MISMATCH"
    RIEC_INVALID_QUANTITY = "RIEC_INVALID_QUANTITY"
    RIEC_INVALID_DEPLOYMENT_GROUP = "RIEC_INVALID_DEPLOYMENT_GROUP"
    RIEC_INSUFFICIENT_GROUPS = "RIEC_INSUFFICIENT_GROUPS"
    RIEC_TOO_MANY_GROUPS_EXACT_LOGO = "RIEC_TOO_MANY_GROUPS_EXACT_LOGO"
    CANDIDATE_REQUIRED_SEMANTIC_MISSING = "CANDIDATE_REQUIRED_SEMANTIC_MISSING"
    CANDIDATE_REQUIRED_COLUMN_MISSING = "CANDIDATE_REQUIRED_COLUMN_MISSING"
    CANDIDATE_INSUFFICIENT_SUPPORT = "CANDIDATE_INSUFFICIENT_SUPPORT"
    CANDIDATE_INSUFFICIENT_LEVELS = "CANDIDATE_INSUFFICIENT_LEVELS"
    CANDIDATE_UNSEEN_LEVEL = "CANDIDATE_UNSEEN_LEVEL"
    CANDIDATE_EMPTY_TRAIN_FOLD = "CANDIDATE_EMPTY_TRAIN_FOLD"
    CANDIDATE_EMPTY_TEST_FOLD = "CANDIDATE_EMPTY_TEST_FOLD"
    CANDIDATE_DESIGN_RANK_DEFICIENT = "CANDIDATE_DESIGN_RANK_DEFICIENT"
    CANDIDATE_FIT_FAILED = "CANDIDATE_FIT_FAILED"
    CANDIDATE_NONFINITE_RESULT = "CANDIDATE_NONFINITE_RESULT"
    RIEC_BASELINE_INELIGIBLE = "RIEC_BASELINE_INELIGIBLE"
    RIEC_SCORE_UNAVAILABLE = "RIEC_SCORE_UNAVAILABLE"
    RIEC_SELECTION_UNAVAILABLE = "RIEC_SELECTION_UNAVAILABLE"
    RIEC_EVIDENCE_APPEND_FAILED = "RIEC_EVIDENCE_APPEND_FAILED"


class DesignFailure(ValueError):
    """Safe deterministic design failure with no rejected data in its message."""

    def __init__(self, code: RiecReasonCode, message: str) -> None:
        super().__init__(message[:300])
        self.code = code


@dataclass(frozen=True, slots=True)
class SemanticSeries:
    semantic: str
    column: str | None
    confirmed: bool
    values: tuple[str, ...] | None


@dataclass(frozen=True, slots=True)
class PreparedDataset:
    response: tuple[float, ...]
    group_keys: tuple[tuple[str, ...], ...]
    group_tokens: tuple[str, ...]
    product: SemanticSeries
    stream: SemanticSeries
    shift: SemanticSeries
    time_hours: tuple[float, ...] | None
    time_column: str | None
    time_confirmed: bool
    row_order: tuple[int, ...]
    n_rows: int
    n_groups: int


@dataclass(frozen=True, slots=True)
class CategoricalEncoding:
    term: str
    levels: tuple[str, ...]
    reference_level: str


@dataclass(frozen=True, slots=True)
class DesignSpecification:
    candidate_id: str
    terms: tuple[str, ...]
    categorical_encodings: tuple[CategoricalEncoding, ...]
    column_names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DesignMatrix:
    values: tuple[tuple[float, ...], ...]
    response: tuple[float, ...]
    row_indices: tuple[int, ...]
    specification: DesignSpecification


def prepare_dataset(normalized_csv: bytes, contract: AuditContract) -> PreparedDataset:
    """Parse normalized bytes using only confirmed contract mappings."""

    header, records = _read_csv(normalized_csv)
    if len(records) != contract.source.row_count or len(header) != contract.source.column_count:
        raise DesignFailure(
            RiecReasonCode.RIEC_DATASET_MISMATCH,
            "Normalized data dimensions do not match the confirmed contract.",
        )

    quantity_column = contract.column_mapping.quantity.column
    if not contract.column_mapping.quantity.confirmed:
        raise DesignFailure(
            RiecReasonCode.RIEC_INVALID_QUANTITY,
            "The quantity mapping is not confirmed.",
        )
    _require_column(header, quantity_column, RiecReasonCode.RIEC_INVALID_QUANTITY)
    if not contract.column_mapping.deployment_group.confirmed:
        raise DesignFailure(
            RiecReasonCode.RIEC_INVALID_DEPLOYMENT_GROUP,
            "The deployment-group mapping is not confirmed.",
        )
    group_columns = tuple(contract.grouping.deployment_group_columns)
    for column in group_columns:
        _require_column(header, column, RiecReasonCode.RIEC_INVALID_DEPLOYMENT_GROUP)

    response = tuple(_converted_quantity(row, header, contract) for row in records)
    group_keys = tuple(
        tuple(_required_cell(row, header, column, group=True) for column in group_columns)
        for row in records
    )
    unique_groups = tuple(sorted(set(group_keys)))
    if len(unique_groups) < 2:
        raise DesignFailure(
            RiecReasonCode.RIEC_INSUFFICIENT_GROUPS,
            "Exact grouped evaluation requires at least two deployment groups.",
        )
    token_by_group = {group: _group_token(group) for group in unique_groups}
    if len(set(token_by_group.values())) != len(token_by_group):
        raise DesignFailure(
            RiecReasonCode.RIEC_INVALID_DEPLOYMENT_GROUP,
            "Deployment-group tokenization was not unique.",
        )

    product = _optional_semantic(
        "product",
        contract.column_mapping.product.column,
        contract.column_mapping.product.confirmed,
        header,
        records,
    )
    stream = _optional_semantic(
        "stream",
        contract.column_mapping.stream.column,
        contract.column_mapping.stream.confirmed,
        header,
        records,
    )
    shift = _optional_semantic(
        "shift",
        contract.column_mapping.shift.column,
        contract.column_mapping.shift.confirmed,
        header,
        records,
    )
    time_ref = contract.column_mapping.time
    time_hours = _time_values(
        time_ref.column,
        time_ref.confirmed,
        contract.ordering.timezone,
        header,
        records,
    )

    provisional = PreparedDataset(
        response=response,
        group_keys=group_keys,
        group_tokens=tuple(token_by_group[group] for group in group_keys),
        product=product,
        stream=stream,
        shift=shift,
        time_hours=time_hours,
        time_column=time_ref.column,
        time_confirmed=time_ref.confirmed,
        row_order=(),
        n_rows=len(response),
        n_groups=len(unique_groups),
    )
    row_order = tuple(
        sorted(range(len(response)), key=lambda index: _row_sort_key(provisional, index))
    )
    return PreparedDataset(
        response=provisional.response,
        group_keys=provisional.group_keys,
        group_tokens=provisional.group_tokens,
        product=provisional.product,
        stream=provisional.stream,
        shift=provisional.shift,
        time_hours=provisional.time_hours,
        time_column=provisional.time_column,
        time_confirmed=provisional.time_confirmed,
        row_order=row_order,
        n_rows=provisional.n_rows,
        n_groups=provisional.n_groups,
    )


def build_training_design(
    dataset: PreparedDataset,
    candidate: CandidateDefinition,
    row_indices: tuple[int, ...],
) -> DesignMatrix:
    """Learn treatment encodings on one training set and build its design matrix."""

    ordered = _canonical_indices(dataset, row_indices)
    if not ordered:
        raise DesignFailure(
            RiecReasonCode.CANDIDATE_EMPTY_TRAIN_FOLD,
            "A grouped training fold is empty.",
        )
    terms = tuple(term.value for term in candidate.formula_terms)
    encodings: list[CategoricalEncoding] = []
    for term in terms:
        if term in {FormulaTerm.INTERCEPT.value, FormulaTerm.TIME.value}:
            if term == FormulaTerm.TIME.value:
                _require_time(dataset)
            continue
        series = _series_for_term(dataset, term)
        values = _require_series(series)
        levels = tuple(sorted({values[index] for index in ordered}))
        if len(levels) < 2:
            raise DesignFailure(
                RiecReasonCode.CANDIDATE_INSUFFICIENT_LEVELS,
                "A required categorical term has fewer than two training levels.",
            )
        encodings.append(CategoricalEncoding(term=term, levels=levels, reference_level=levels[0]))
    specification = DesignSpecification(
        candidate_id=candidate.candidate_id,
        terms=terms,
        categorical_encodings=tuple(encodings),
        column_names=_column_names(terms, tuple(encodings)),
    )
    return _build_design(dataset, ordered, specification)


def build_prediction_design(
    dataset: PreparedDataset,
    specification: DesignSpecification,
    row_indices: tuple[int, ...],
) -> DesignMatrix:
    """Apply a training-owned design specification to held-out rows."""

    ordered = _canonical_indices(dataset, row_indices)
    if not ordered:
        raise DesignFailure(
            RiecReasonCode.CANDIDATE_EMPTY_TEST_FOLD,
            "A grouped test fold is empty.",
        )
    for encoding in specification.categorical_encodings:
        values = _require_series(_series_for_term(dataset, encoding.term))
        if any(values[index] not in encoding.levels for index in ordered):
            raise DesignFailure(
                RiecReasonCode.CANDIDATE_UNSEEN_LEVEL,
                "A held-out fold contains a categorical level absent from training.",
            )
    return _build_design(dataset, ordered, specification)


def candidate_semantics_available(
    dataset: PreparedDataset, candidate: CandidateDefinition
) -> tuple[bool, RiecReasonCode | None]:
    """Return whether every frozen semantic required by a candidate is available."""

    for term in candidate.formula_terms:
        if term is FormulaTerm.INTERCEPT:
            continue
        if term is FormulaTerm.TIME:
            if not dataset.time_confirmed or dataset.time_column is None:
                return False, RiecReasonCode.CANDIDATE_REQUIRED_SEMANTIC_MISSING
            if dataset.time_hours is None:
                return False, RiecReasonCode.CANDIDATE_REQUIRED_COLUMN_MISSING
            continue
        series = _series_for_term(dataset, term.value)
        if not series.confirmed or series.column is None:
            return False, RiecReasonCode.CANDIDATE_REQUIRED_SEMANTIC_MISSING
        if series.values is None:
            return False, RiecReasonCode.CANDIDATE_REQUIRED_COLUMN_MISSING
    return True, None


def _read_csv(payload: bytes) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...]]:
    try:
        text = payload.decode("utf-8-sig", errors="strict")
        # Profiling canonically strips CSV cells before it creates the confirmed
        # mappings/profile. Repeat that exact accepted convention here and reject
        # any header collision after canonicalization; do not invent other repairs.
        rows = tuple(
            tuple(cell.strip() for cell in row)
            for row in csv.reader(io.StringIO(text, newline=""), strict=True)
        )
    except (UnicodeError, csv.Error):
        raise DesignFailure(
            RiecReasonCode.RIEC_DATASET_MISMATCH,
            "Normalized data is not valid UTF-8 CSV.",
        ) from None
    if not rows or not rows[0]:
        raise DesignFailure(
            RiecReasonCode.RIEC_DATASET_MISMATCH,
            "Normalized data has no header.",
        )
    header = rows[0]
    if any(not name for name in header) or len(set(header)) != len(header):
        raise DesignFailure(
            RiecReasonCode.RIEC_DATASET_MISMATCH,
            "Normalized data has an invalid header.",
        )
    records = rows[1:]
    if not records or any(len(row) != len(header) for row in records):
        raise DesignFailure(
            RiecReasonCode.RIEC_DATASET_MISMATCH,
            "Normalized data rows do not match the header.",
        )
    return header, records


def _converted_quantity(
    row: tuple[str, ...], header: tuple[str, ...], contract: AuditContract
) -> float:
    conversion = contract.measurement.conversion
    method = conversion.method
    if method is ConversionMethod.GROSS_MINUS_TARE:
        weight_ref = contract.column_mapping.weight
        tare_ref = contract.column_mapping.tare
        if (
            weight_ref is None
            or tare_ref is None
            or not weight_ref.confirmed
            or not tare_ref.confirmed
            or weight_ref.column is None
            or tare_ref.column is None
        ):
            return _invalid_quantity()
        value = _numeric_cell(row, header, weight_ref.column) - _numeric_cell(
            row, header, tare_ref.column
        )
    else:
        value = _numeric_cell(row, header, contract.column_mapping.quantity.column)
        if method is ConversionMethod.FIXED_DENSITY:
            density = conversion.fixed_density
            if density is None or density <= 0:
                return _invalid_quantity()
            value /= float(density)
        elif method is ConversionMethod.ROW_DENSITY:
            density_ref = contract.column_mapping.density
            if density_ref is None or not density_ref.confirmed or density_ref.column is None:
                return _invalid_quantity()
            density = _numeric_cell(row, header, density_ref.column)
            if density <= 0:
                return _invalid_quantity()
            value /= density
        elif method is ConversionMethod.CUSTOM:
            return _invalid_quantity()
    if not math.isfinite(value):
        return _invalid_quantity()
    return value


def _invalid_quantity() -> float:
    raise DesignFailure(
        RiecReasonCode.RIEC_INVALID_QUANTITY,
        "A required adjusted quantity is invalid or unsupported.",
    )


def _numeric_cell(row: tuple[str, ...], header: tuple[str, ...], column: str) -> float:
    _require_column(header, column, RiecReasonCode.RIEC_INVALID_QUANTITY)
    raw = row[header.index(column)]
    if not raw:
        return _invalid_quantity()
    try:
        value = float(raw)
    except ValueError:
        return _invalid_quantity()
    if not math.isfinite(value):
        return _invalid_quantity()
    return value


def _required_cell(
    row: tuple[str, ...], header: tuple[str, ...], column: str, *, group: bool
) -> str:
    _require_column(
        header,
        column,
        RiecReasonCode.RIEC_INVALID_DEPLOYMENT_GROUP
        if group
        else RiecReasonCode.RIEC_DATASET_MISMATCH,
    )
    value = row[header.index(column)]
    if not value:
        raise DesignFailure(
            RiecReasonCode.RIEC_INVALID_DEPLOYMENT_GROUP,
            "A deployment-group value is missing.",
        )
    return value


def _optional_semantic(
    semantic: str,
    column: str | None,
    confirmed: bool,
    header: tuple[str, ...],
    records: tuple[tuple[str, ...], ...],
) -> SemanticSeries:
    if column is None or not confirmed:
        return SemanticSeries(semantic, column, confirmed, None)
    if column not in header:
        return SemanticSeries(semantic, column, confirmed, None)
    offset = header.index(column)
    values = tuple(row[offset] for row in records)
    if any(not value for value in values):
        return SemanticSeries(semantic, column, confirmed, None)
    return SemanticSeries(semantic, column, confirmed, values)


def _time_values(
    column: str | None,
    confirmed: bool,
    declared_timezone: str | None,
    header: tuple[str, ...],
    records: tuple[tuple[str, ...], ...],
) -> tuple[float, ...] | None:
    if column is None or not confirmed or column not in header:
        return None
    offset = header.index(column)
    instants: list[float] = []
    for row in records:
        raw = row[offset]
        if not raw:
            return None
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                if declared_timezone is None:
                    return None
                parsed = parsed.replace(tzinfo=ZoneInfo(declared_timezone))
            instant = parsed.astimezone(timezone.utc).timestamp()
        except (ValueError, OverflowError, OSError, ZoneInfoNotFoundError):
            return None
        if not math.isfinite(instant):
            return None
        instants.append(instant)
    origin = min(instants)
    return tuple((instant - origin) / 3600.0 for instant in instants)


def _group_token(group: tuple[str, ...]) -> str:
    encoded = json.dumps(group, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return f"GRP-{hashlib.sha256(encoded).hexdigest()[:16].upper()}"


def _row_sort_key(dataset: PreparedDataset, index: int) -> tuple[str, ...]:
    def value(series: SemanticSeries) -> str:
        return "" if series.values is None else series.values[index]

    time_value = "" if dataset.time_hours is None else float(dataset.time_hours[index]).hex()
    return (
        value(dataset.product),
        value(dataset.stream),
        value(dataset.shift),
        time_value,
        float(dataset.response[index]).hex(),
    )


def _canonical_indices(dataset: PreparedDataset, indices: tuple[int, ...]) -> tuple[int, ...]:
    if len(set(indices)) != len(indices) or any(
        index < 0 or index >= dataset.n_rows for index in indices
    ):
        raise DesignFailure(
            RiecReasonCode.RIEC_DATASET_MISMATCH,
            "Design row indices are invalid.",
        )
    selected = set(indices)
    return tuple(index for index in dataset.row_order if index in selected)


def _series_for_term(dataset: PreparedDataset, term: str) -> SemanticSeries:
    if term == FormulaTerm.PRODUCT.value:
        return dataset.product
    if term == FormulaTerm.STREAM.value:
        return dataset.stream
    if term == FormulaTerm.SHIFT.value:
        return dataset.shift
    raise DesignFailure(
        RiecReasonCode.CANDIDATE_REQUIRED_SEMANTIC_MISSING,
        "The candidate requests an unsupported semantic term.",
    )


def _require_series(series: SemanticSeries) -> tuple[str, ...]:
    if not series.confirmed or series.column is None:
        raise DesignFailure(
            RiecReasonCode.CANDIDATE_REQUIRED_SEMANTIC_MISSING,
            "A candidate-required semantic is not confirmed.",
        )
    if series.values is None:
        raise DesignFailure(
            RiecReasonCode.CANDIDATE_REQUIRED_COLUMN_MISSING,
            "A candidate-required column is unavailable or invalid.",
        )
    return series.values


def _require_time(dataset: PreparedDataset) -> tuple[float, ...]:
    if not dataset.time_confirmed or dataset.time_column is None:
        raise DesignFailure(
            RiecReasonCode.CANDIDATE_REQUIRED_SEMANTIC_MISSING,
            "The candidate-required time semantic is not confirmed.",
        )
    if dataset.time_hours is None:
        raise DesignFailure(
            RiecReasonCode.CANDIDATE_REQUIRED_COLUMN_MISSING,
            "The candidate-required time column is unavailable or invalid.",
        )
    return dataset.time_hours


def _column_names(
    terms: tuple[str, ...], encodings: tuple[CategoricalEncoding, ...]
) -> tuple[str, ...]:
    names: list[str] = []
    for term in terms:
        if term == FormulaTerm.INTERCEPT.value:
            names.append("intercept")
        elif term == FormulaTerm.TIME.value:
            names.append("time_elapsed_hours")
        else:
            encoding = next(item for item in encodings if item.term == term)
            names.extend(f"{term}[{index}]" for index in range(1, len(encoding.levels)))
    return tuple(names)


def _build_design(
    dataset: PreparedDataset,
    ordered: tuple[int, ...],
    specification: DesignSpecification,
) -> DesignMatrix:
    encodings = {encoding.term: encoding for encoding in specification.categorical_encodings}
    rows: list[tuple[float, ...]] = []
    for index in ordered:
        cells: list[float] = []
        for term in specification.terms:
            if term == FormulaTerm.INTERCEPT.value:
                cells.append(1.0)
            elif term == FormulaTerm.TIME.value:
                cells.append(_require_time(dataset)[index])
            else:
                values = _require_series(_series_for_term(dataset, term))
                encoding = encodings[term]
                value = values[index]
                if value not in encoding.levels:
                    raise DesignFailure(
                        RiecReasonCode.CANDIDATE_UNSEEN_LEVEL,
                        "A design row contains a level absent from training.",
                    )
                cells.extend(1.0 if value == level else 0.0 for level in encoding.levels[1:])
        if not cells or any(not math.isfinite(cell) for cell in cells):
            raise DesignFailure(
                RiecReasonCode.CANDIDATE_NONFINITE_RESULT,
                "A candidate design matrix is invalid.",
            )
        rows.append(tuple(cells))
    return DesignMatrix(
        values=tuple(rows),
        response=tuple(dataset.response[index] for index in ordered),
        row_indices=ordered,
        specification=specification,
    )


def _require_column(header: tuple[str, ...], column: str, code: RiecReasonCode) -> None:
    if column not in header:
        raise DesignFailure(code, "A required confirmed column is unavailable.")


__all__ = [
    "CategoricalEncoding",
    "DesignFailure",
    "DesignMatrix",
    "DesignSpecification",
    "PreparedDataset",
    "RiecReasonCode",
    "SemanticSeries",
    "build_prediction_design",
    "build_training_design",
    "candidate_semantics_available",
    "prepare_dataset",
]
