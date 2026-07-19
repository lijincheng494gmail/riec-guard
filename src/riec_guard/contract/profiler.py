from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime

from riec_guard.contract.models import (
    CandidateSemanticMapping,
    ColumnDataType,
    ColumnProfile,
    DatasetProfile,
    NumericSummary,
    PrivacyRedaction,
    SemanticRole,
)
from riec_guard.domain.source import SourceRepository
from riec_guard.errors import ApplicationError, ErrorClass, ErrorEnvelope, ErrorStage

_INTEGER_PATTERN = re.compile(r"[+-]?[0-9]+\Z")
_NUMBER_PATTERN = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\Z")
_NONFINITE_PATTERN = re.compile(r"[+-]?(?:nan|inf|infinity)\Z", re.IGNORECASE)
_SAFE_HEADER_TOKEN_PATTERN = re.compile(r"[^a-z0-9]+")
_EMAIL_LOCAL_ATOM = r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+"
_EMAIL_SHAPE_PATTERN = re.compile(
    rf"{_EMAIL_LOCAL_ATOM}(?:\.{_EMAIL_LOCAL_ATOM})*@"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z",
    re.IGNORECASE | re.ASCII,
)
_PHONE_ALLOWED_SHAPE_PATTERN = re.compile(
    r"\+?(?:[0-9]|\()[0-9() -]*[0-9]\Z",
    re.ASCII,
)
_PHONE_GROUPED_SHAPE_PATTERN = re.compile(
    r"[0-9]{1,4}(?:[ -][0-9]{1,4}){1,4}\Z",
    re.ASCII,
)
_PHONE_PARENTHESIZED_SHAPE_PATTERN = re.compile(
    r"(?:[0-9]{1,3}[ -]?)?\([0-9]{2,4}\)(?:[ -]?[0-9]{2,4}){1,3}\Z",
    re.ASCII,
)
_PHONE_PLUS_CONTIGUOUS_SHAPE_PATTERN = re.compile(r"[0-9]{7,15}\Z", re.ASCII)
_YEAR_FIRST_DATE_SHAPE_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}\Z",
    re.ASCII,
)
_MAX_EMAIL_SHAPE_LENGTH = 254
_MAX_EMAIL_LOCAL_PART_LENGTH = 64
_MAX_EMAIL_DOMAIN_LENGTH = 253
_MAX_PHONE_SHAPE_LENGTH = 40
_MIN_PHONE_DIGITS = 7
_MAX_PHONE_DIGITS = 15
_DATETIME_NAME_HINTS = frozenset(
    {
        "date",
        "datetime",
        "production_date",
        "production_datetime",
        "sample_date",
        "sample_time",
        "time",
        "timestamp",
    }
)
_ROW_ID_NAMES = frozenset({"row_id", "record_id", "sample_id", "observation_id"})
_DIRECT_IDENTIFIER_TERMS = frozenset(
    {
        "account",
        "address",
        "client",
        "contact",
        "customer",
        "email",
        "employee",
        "name",
        "operator",
        "person",
        "personal",
        "phone",
        "user",
    }
)
_SEMANTIC_ROLE_ORDER = (
    SemanticRole.QUANTITY,
    SemanticRole.PRODUCT,
    SemanticRole.DEPLOYMENT_GROUP,
    SemanticRole.TIME,
    SemanticRole.STREAM,
    SemanticRole.SHIFT,
    SemanticRole.WEIGHT,
    SemanticRole.DENSITY,
    SemanticRole.TARE,
)
_SEMANTIC_NAME_HINTS: dict[SemanticRole, frozenset[str]] = {
    SemanticRole.QUANTITY: frozenset(
        {
            "quantity",
            "fill",
            "volume",
            "net_volume",
            "net_content",
            "weight",
            "mass",
            "actual_ml",
            "measured_ml",
            "measured_g",
        }
    ),
    SemanticRole.PRODUCT: frozenset({"sku", "product", "formula", "recipe", "variant"}),
    SemanticRole.DEPLOYMENT_GROUP: frozenset(
        {
            "batch_id",
            "lot_id",
            "production_run",
            "group_id",
            "campaign_id",
            "production_date",
            "date_shift",
            "day",
        }
    ),
    SemanticRole.TIME: frozenset(
        {
            "timestamp",
            "sample_time",
            "production_datetime",
            "sequence",
            "row_sequence",
        }
    ),
    SemanticRole.STREAM: frozenset(
        {"nozzle", "filler_head", "claw", "line", "machine", "pump", "stream"}
    ),
    SemanticRole.SHIFT: frozenset({"shift", "crew_period", "day_night"}),
    SemanticRole.WEIGHT: frozenset({"weight", "gross_weight", "net_weight", "measured_g"}),
    SemanticRole.DENSITY: frozenset({"density", "row_density"}),
    SemanticRole.TARE: frozenset({"tare", "tare_weight"}),
}
_NUMERIC_ROLES = frozenset(
    {SemanticRole.QUANTITY, SemanticRole.WEIGHT, SemanticRole.DENSITY, SemanticRole.TARE}
)


@dataclass(frozen=True, slots=True)
class ProfilerConfig:
    """Deterministic limits and the single named categorical-redaction policy."""

    max_bytes: int = 10 * 1024 * 1024
    max_rows: int = 100_000
    max_columns: int = 100
    high_cardinality_unique_count: int = 20
    high_cardinality_unique_fraction: float = 0.20

    def __post_init__(self) -> None:
        if self.max_bytes <= 0 or self.max_rows <= 0 or self.max_columns <= 0:
            raise ValueError("profiler limits must be positive")
        if self.high_cardinality_unique_count < 0:
            raise ValueError("high_cardinality_unique_count must be nonnegative")
        if not 0 <= self.high_cardinality_unique_fraction <= 1:
            raise ValueError("high_cardinality_unique_fraction must be between zero and one")


@dataclass(frozen=True, slots=True)
class SemanticHint:
    semantic_role: SemanticRole
    column: str


@dataclass(frozen=True, slots=True)
class ProfilingHints:
    semantic_hints: tuple[SemanticHint, ...] = ()
    row_id_column: str | None = None


@dataclass(frozen=True, slots=True)
class _ColumnScan:
    name: str
    source_index: int
    values: tuple[str, ...]
    nonmissing_values: tuple[str, ...]
    missing_count: int
    unique_values: tuple[str, ...]
    dtype: ColumnDataType
    finite_numeric_count: int
    numeric_parse_failure_count: int
    datetime_parse_count: int
    numeric_values: tuple[int | float, ...]


@dataclass(frozen=True, slots=True)
class _DatasetScan:
    normalized_bytes: bytes
    row_count: int
    columns: tuple[_ColumnScan, ...]


class _ProfileFailure(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        error_class: ErrorClass = ErrorClass.VALIDATION,
        safe_details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.error_class = error_class
        self.safe_details = safe_details or {}


def profile_dataset(
    repository: SourceRepository,
    *,
    run_id: str,
    source_id: str,
    hints: ProfilingHints | None = None,
    config: ProfilerConfig | None = None,
) -> DatasetProfile | ErrorEnvelope:
    """Return a canonical redacted profile or canonical safe profile-stage error."""

    active_config = config or ProfilerConfig()
    active_hints = hints or ProfilingHints()
    try:
        normalized_bytes = repository.read_normalized_bytes(run_id, source_id)
    except ApplicationError:
        return _error_envelope(
            "PROFILE_SOURCE_NOT_FOUND",
            "The requested normalized dataset was not found for this run.",
            safe_details={},
        )

    try:
        scan = _scan_normalized_csv(normalized_bytes, active_config)
        resolved_hints = _resolve_hints(scan, active_hints)
        _validate_nonfinite(scan)
        _validate_quantity_columns(scan, resolved_hints)
        _validate_row_ids(scan, resolved_hints)
        mappings = _candidate_semantic_mappings(scan, resolved_hints)
        if not any(mapping.semantic_role is SemanticRole.QUANTITY for mapping in mappings):
            raise _ProfileFailure(
                "PROFILE_MISSING_QUANTITY",
                "No plausible finite numeric quantity column was found.",
                error_class=ErrorClass.DATA_QUALITY,
                safe_details={"column_count": len(scan.columns)},
            )
        return _build_profile(scan, mappings, active_config)
    except _ProfileFailure as error:
        return _error_envelope(
            error.code,
            error.message,
            error_class=error.error_class,
            safe_details=error.safe_details,
        )


def _scan_normalized_csv(data: bytes, config: ProfilerConfig) -> _DatasetScan:
    if len(data) > config.max_bytes:
        raise _limit_failure("bytes", config.max_bytes)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise _invalid_csv() from None
    if "\x00" in text:
        raise _invalid_csv()

    try:
        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        raw_header = next(reader, None)
        if raw_header is None:
            raise _ProfileFailure(
                "PROFILE_EMPTY_DATASET",
                "The normalized dataset is empty.",
                safe_details={"row_count": 0},
            )
        if not raw_header:
            raise _invalid_csv()
        if len(raw_header) > config.max_columns:
            raise _limit_failure("columns", config.max_columns)
        header = tuple(_normalize_column_name(name, index) for index, name in enumerate(raw_header))
        folded_names: dict[str, int] = {}
        for index, name in enumerate(header):
            folded = name.casefold()
            previous = folded_names.get(folded)
            if previous is not None:
                raise _ProfileFailure(
                    "PROFILE_DUPLICATE_COLUMN_NAME",
                    "The normalized dataset contains duplicate column names.",
                    safe_details={"first_column_index": previous, "column_index": index},
                )
            folded_names[folded] = index

        values_by_column: list[list[str]] = [[] for _ in header]
        row_count = 0
        for row in reader:
            row_count += 1
            if row_count > config.max_rows:
                raise _limit_failure("rows", config.max_rows)
            if len(row) != len(header):
                raise _invalid_csv(row_index=row_count)
            for index, raw_value in enumerate(row):
                if "\x00" in raw_value:
                    raise _invalid_csv(row_index=row_count, column_index=index)
                values_by_column[index].append(raw_value.strip())
    except csv.Error:
        raise _invalid_csv() from None

    if row_count == 0:
        raise _ProfileFailure(
            "PROFILE_EMPTY_DATASET",
            "The normalized dataset contains no data rows.",
            safe_details={"row_count": 0, "column_count": len(header)},
        )
    columns = tuple(
        _scan_column(name, index, tuple(values_by_column[index]))
        for index, name in enumerate(header)
    )
    return _DatasetScan(normalized_bytes=data, row_count=row_count, columns=columns)


def _normalize_column_name(name: str, index: int) -> str:
    normalized = name.strip()
    if (
        not normalized
        or len(normalized) > 128
        or normalized in {".", ".."}
        or "/" in normalized
        or "\\" in normalized
        or unicodedata.normalize("NFKC", normalized) != normalized
        or any(
            character == "\x00" or unicodedata.category(character) == "Cc"
            for character in normalized
        )
    ):
        raise _ProfileFailure(
            "PROFILE_INVALID_COLUMN_NAME",
            "The normalized dataset contains an unusable column name.",
            safe_details={"column_index": index},
        )
    return normalized


def _scan_column(name: str, source_index: int, values: tuple[str, ...]) -> _ColumnScan:
    nonmissing = tuple(value for value in values if value != "")
    unique_values = tuple(sorted(set(nonmissing)))
    finite_numeric_count = 0
    numeric_parse_failure_count = 0
    parsed_numeric: list[int | float] = []
    datetime_parse_count = 0
    for value in nonmissing:
        parsed = _parse_finite_number(value)
        if parsed is None:
            numeric_parse_failure_count += 1
        else:
            finite_numeric_count += 1
            parsed_numeric.append(parsed)
        if _parse_datetime(value):
            datetime_parse_count += 1

    dtype = _infer_dtype(name, nonmissing, tuple(parsed_numeric), datetime_parse_count)
    numeric_values: tuple[int | float, ...]
    if dtype in {ColumnDataType.INTEGER, ColumnDataType.NUMBER}:
        numeric_values = tuple(parsed_numeric)
    else:
        numeric_values = ()
    return _ColumnScan(
        name=name,
        source_index=source_index,
        values=values,
        nonmissing_values=nonmissing,
        missing_count=len(values) - len(nonmissing),
        unique_values=unique_values,
        dtype=dtype,
        finite_numeric_count=finite_numeric_count,
        numeric_parse_failure_count=numeric_parse_failure_count,
        datetime_parse_count=datetime_parse_count,
        numeric_values=numeric_values,
    )


def _infer_dtype(
    name: str,
    values: tuple[str, ...],
    parsed_numeric: tuple[int | float, ...],
    datetime_parse_count: int,
) -> ColumnDataType:
    """Apply boolean, integer, finite number, credible datetime, string, unknown precedence."""

    if not values:
        return ColumnDataType.UNKNOWN
    if all(value.casefold() in {"true", "false"} for value in values):
        return ColumnDataType.BOOLEAN
    if len(parsed_numeric) == len(values) and all(
        _INTEGER_PATTERN.fullmatch(value) for value in values
    ):
        return ColumnDataType.INTEGER
    if len(parsed_numeric) == len(values):
        return ColumnDataType.NUMBER
    if _normalized_name(name) in _DATETIME_NAME_HINTS and datetime_parse_count == len(values):
        return ColumnDataType.DATETIME
    return ColumnDataType.STRING


def _parse_finite_number(value: str) -> int | float | None:
    if _INTEGER_PATTERN.fullmatch(value):
        try:
            return int(value)
        except ValueError:
            return None
    if not _NUMBER_PATTERN.fullmatch(value):
        return None
    parsed = float(value)
    if not math.isfinite(parsed):
        return None
    return parsed


def _parse_datetime(value: str) -> bool:
    if not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[T ][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]{1,6})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})?)?",
        value,
    ):
        return False
    try:
        datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return False
    return True


def _resolve_hints(scan: _DatasetScan, hints: ProfilingHints) -> ProfilingHints:
    by_folded_name = {column.name.casefold(): column.name for column in scan.columns}
    resolved_semantics: list[SemanticHint] = []
    for hint in hints.semantic_hints:
        column = by_folded_name.get(hint.column.strip().casefold())
        if column is not None:
            resolved_semantics.append(SemanticHint(hint.semantic_role, column))
    row_id_column = None
    if hints.row_id_column is not None:
        row_id_column = by_folded_name.get(hints.row_id_column.strip().casefold())
    return ProfilingHints(tuple(resolved_semantics), row_id_column)


def _validate_nonfinite(scan: _DatasetScan) -> None:
    for column in scan.columns:
        count = sum(1 for value in column.nonmissing_values if _NONFINITE_PATTERN.fullmatch(value))
        if count:
            raise _ProfileFailure(
                "PROFILE_NONFINITE_VALUE",
                "The normalized dataset contains a non-finite numeric value.",
                error_class=ErrorClass.DATA_QUALITY,
                safe_details={"column_index": column.source_index, "nonfinite_count": count},
            )
        overflow_count = sum(
            1
            for value in column.nonmissing_values
            if _NUMBER_PATTERN.fullmatch(value)
            and not _INTEGER_PATTERN.fullmatch(value)
            and not math.isfinite(float(value))
        )
        if overflow_count:
            raise _ProfileFailure(
                "PROFILE_NONFINITE_VALUE",
                "The normalized dataset contains a non-finite numeric value.",
                error_class=ErrorClass.DATA_QUALITY,
                safe_details={
                    "column_index": column.source_index,
                    "nonfinite_count": overflow_count,
                },
            )


def _validate_quantity_columns(scan: _DatasetScan, hints: ProfilingHints) -> None:
    supplied = {
        hint.column.casefold()
        for hint in hints.semantic_hints
        if hint.semantic_role is SemanticRole.QUANTITY
    }
    for column in scan.columns:
        normalized_name = _normalized_name(column.name)
        if (
            normalized_name not in _SEMANTIC_NAME_HINTS[SemanticRole.QUANTITY]
            and column.name.casefold() not in supplied
        ):
            continue
        malformed_count = len(column.nonmissing_values) - column.finite_numeric_count
        if malformed_count:
            raise _ProfileFailure(
                "PROFILE_MALFORMED_NUMERIC",
                "A supplied or strongly quantity-hinted column contains malformed numeric data.",
                error_class=ErrorClass.DATA_QUALITY,
                safe_details={
                    "column_index": column.source_index,
                    "malformed_count": malformed_count,
                },
            )


def _validate_row_ids(scan: _DatasetScan, hints: ProfilingHints) -> None:
    supplied = hints.row_id_column.casefold() if hints.row_id_column is not None else None
    for column in scan.columns:
        normalized_name = _normalized_name(column.name)
        if normalized_name not in _ROW_ID_NAMES and column.name.casefold() != supplied:
            continue
        duplicate_count = len(column.nonmissing_values) - len(set(column.nonmissing_values))
        if duplicate_count:
            raise _ProfileFailure(
                "PROFILE_DUPLICATE_ROW_ID",
                "A credible row-identity column contains duplicate nonmissing identifiers.",
                error_class=ErrorClass.DATA_QUALITY,
                safe_details={
                    "column_index": column.source_index,
                    "duplicate_count": duplicate_count,
                },
            )


def _candidate_semantic_mappings(
    scan: _DatasetScan, hints: ProfilingHints
) -> tuple[CandidateSemanticMapping, ...]:
    candidates: dict[tuple[SemanticRole, str], tuple[float, list[str]]] = {}
    column_by_name = {column.name: column for column in scan.columns}
    for hint in hints.semantic_hints:
        column = column_by_name[hint.column]
        if hint.semantic_role in _NUMERIC_ROLES and column.dtype not in {
            ColumnDataType.INTEGER,
            ColumnDataType.NUMBER,
        }:
            continue
        candidates[(hint.semantic_role, column.name)] = (
            0.99,
            ["supplied: caller-provided semantic hint; suggestion only, not confirmed"],
        )

    for column in scan.columns:
        normalized_name = _normalized_name(column.name)
        for role in _SEMANTIC_ROLE_ORDER:
            if normalized_name not in _SEMANTIC_NAME_HINTS[role]:
                continue
            if role in _NUMERIC_ROLES and column.dtype not in {
                ColumnDataType.INTEGER,
                ColumnDataType.NUMBER,
            }:
                continue
            if role is SemanticRole.TIME and not (
                column.dtype is ColumnDataType.DATETIME
                or (
                    normalized_name in {"sequence", "row_sequence"}
                    and column.dtype in {ColumnDataType.INTEGER, ColumnDataType.NUMBER}
                )
            ):
                continue
            if column.dtype is ColumnDataType.UNKNOWN:
                continue
            confidence = 0.95 if role is SemanticRole.QUANTITY else 0.85
            reason = (
                "inferred: strong name and finite numeric type suggest quantity; not confirmed"
                if role is SemanticRole.QUANTITY
                else f"inferred: normalized column name and compatible type suggest {role.value}; not confirmed"
            )
            key = (role, column.name)
            if key in candidates:
                previous_confidence, reasons = candidates[key]
                candidates[key] = (max(previous_confidence, confidence), [*reasons, reason])
            else:
                candidates[key] = (confidence, [reason])

    role_positions = {role: index for index, role in enumerate(_SEMANTIC_ROLE_ORDER)}
    column_positions = {column.name: column.source_index for column in scan.columns}
    ordered = sorted(
        candidates.items(),
        key=lambda item: (
            role_positions[item[0][0]],
            -item[1][0],
            column_positions[item[0][1]],
            item[0][1],
        ),
    )
    return tuple(
        CandidateSemanticMapping.model_validate(
            {
                "semantic_role": role,
                "column": column,
                "confidence": confidence,
                "reasons": tuple(dict.fromkeys(reasons)),
            }
        )
        for (role, column), (confidence, reasons) in ordered
    )


def _build_profile(
    scan: _DatasetScan,
    mappings: tuple[CandidateSemanticMapping, ...],
    config: ProfilerConfig,
) -> DatasetProfile:
    digest = hashlib.sha256(scan.normalized_bytes).hexdigest()
    column_profiles = tuple(
        _build_column_profile(column, scan.row_count, config) for column in scan.columns
    )
    return DatasetProfile.model_validate(
        {
            "schema_version": "1.0.0",
            "dataset_id": f"dataset-{digest[:16]}",
            "dataset_sha256": digest,
            "row_count": scan.row_count,
            "column_profiles": column_profiles,
            "candidate_semantic_mappings": mappings,
            "privacy_redaction": PrivacyRedaction.model_validate(
                {
                    "raw_rows_included": False,
                    "direct_identifiers_included": False,
                    "high_cardinality_values_included": False,
                }
            ),
        }
    )


def _build_column_profile(
    column: _ColumnScan,
    row_count: int,
    config: ProfilerConfig,
) -> ColumnProfile:
    is_identifier = _looks_like_direct_identifier(column.name) or any(
        _looks_like_direct_identifier_value(value) for value in column.nonmissing_values
    )
    numeric_summary = None
    safe_examples: tuple[object, ...] = ()
    if column.dtype in {ColumnDataType.INTEGER, ColumnDataType.NUMBER} and not is_identifier:
        minimum, middle, maximum = _numeric_aggregates(column.numeric_values)
        numeric_summary = NumericSummary.model_validate(
            {"min": minimum, "median": middle, "max": maximum}
        )
        safe_examples = tuple(dict.fromkeys((minimum, middle, maximum)))
    elif column.dtype is ColumnDataType.BOOLEAN and not is_identifier:
        safe_examples = tuple(
            value == "true"
            for value in sorted({value.casefold() for value in column.nonmissing_values})
        )[:3]
    elif column.dtype is ColumnDataType.STRING and not is_identifier:
        nonmissing_count = len(column.nonmissing_values)
        unique_count = len(column.unique_values)
        unique_fraction = unique_count / nonmissing_count if nonmissing_count else 0.0
        high_cardinality = (
            unique_count > config.high_cardinality_unique_count
            or unique_fraction > config.high_cardinality_unique_fraction
        )
        if not high_cardinality and all(len(value) <= 80 for value in column.unique_values):
            safe_examples = column.unique_values[:3]

    return ColumnProfile.model_validate(
        {
            "name": column.name,
            "dtype": column.dtype,
            "missing_fraction": column.missing_count / row_count,
            "unique_count": len(column.unique_values),
            "safe_examples": safe_examples,
            "numeric_summary": numeric_summary,
        }
    )


def _numeric_aggregates(values: tuple[int | float, ...]) -> tuple[int | float, float, int | float]:
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        median = float(ordered[midpoint])
    else:
        median = (ordered[midpoint - 1] + ordered[midpoint]) / 2
    return ordered[0], median, ordered[-1]


def _normalized_name(name: str) -> str:
    return _SAFE_HEADER_TOKEN_PATTERN.sub("_", name.strip().casefold()).strip("_")


def _looks_like_direct_identifier(name: str) -> bool:
    normalized = _normalized_name(name)
    tokens = frozenset(token for token in normalized.split("_") if token)
    return bool(tokens & _DIRECT_IDENTIFIER_TERMS) or any(
        term in normalized for term in _DIRECT_IDENTIFIER_TERMS
    )


def _looks_like_direct_identifier_value(value: str) -> bool:
    return _looks_like_email_address(value) or _looks_like_phone_contact(value)


def _looks_like_email_address(value: str) -> bool:
    if not 6 <= len(value) <= _MAX_EMAIL_SHAPE_LENGTH or value.count("@") != 1:
        return False
    local_part, domain = value.rsplit("@", 1)
    if (
        not local_part
        or len(local_part) > _MAX_EMAIL_LOCAL_PART_LENGTH
        or not domain
        or len(domain) > _MAX_EMAIL_DOMAIN_LENGTH
    ):
        return False
    top_level_label = domain.rsplit(".", 1)[-1]
    if len(top_level_label) < 2 or not any(
        "a" <= character.casefold() <= "z" for character in top_level_label
    ):
        return False
    return _EMAIL_SHAPE_PATTERN.fullmatch(value) is not None


def _looks_like_phone_contact(value: str) -> bool:
    if not 7 <= len(value) <= _MAX_PHONE_SHAPE_LENGTH:
        return False
    if _parse_datetime(value) or _YEAR_FIRST_DATE_SHAPE_PATTERN.fullmatch(value):
        return False
    if _PHONE_ALLOWED_SHAPE_PATTERN.fullmatch(value) is None:
        return False
    digit_count = sum(character in "0123456789" for character in value)
    if not _MIN_PHONE_DIGITS <= digit_count <= _MAX_PHONE_DIGITS:
        return False

    has_leading_plus = value.startswith("+")
    body = value[1:] if has_leading_plus else value
    if _PHONE_GROUPED_SHAPE_PATTERN.fullmatch(body):
        return True
    if _PHONE_PARENTHESIZED_SHAPE_PATTERN.fullmatch(body):
        return True
    return bool(has_leading_plus and _PHONE_PLUS_CONTIGUOUS_SHAPE_PATTERN.fullmatch(body))


def _invalid_csv(
    *, row_index: int | None = None, column_index: int | None = None
) -> _ProfileFailure:
    details: dict[str, object] = {}
    if row_index is not None:
        details["row_index"] = row_index
    if column_index is not None:
        details["column_index"] = column_index
    return _ProfileFailure(
        "PROFILE_INVALID_NORMALIZED_CSV",
        "The normalized dataset is not a valid bounded UTF-8 CSV.",
        safe_details=details,
    )


def _limit_failure(limit_kind: str, configured_limit: int) -> _ProfileFailure:
    return _ProfileFailure(
        "PROFILE_LIMIT_EXCEEDED",
        "The normalized dataset exceeds a configured profiling limit.",
        safe_details={"limit_kind": limit_kind, "configured_limit": configured_limit},
    )


def _error_envelope(
    code: str,
    message: str,
    *,
    error_class: ErrorClass = ErrorClass.VALIDATION,
    safe_details: dict[str, object],
) -> ErrorEnvelope:
    fingerprint = json.dumps(
        {"code": code, "safe_details": safe_details},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return ErrorEnvelope.model_validate(
        {
            "schema_version": "1.0.0",
            "error_id": f"ERR-{hashlib.sha256(fingerprint).hexdigest()[:12].upper()}",
            "stage": ErrorStage.PROFILE,
            "error_class": error_class,
            "code": code,
            "message": message,
            "recoverable": True,
            "user_action": "Correct or select a bounded public CSV source and profile it again.",
            "safe_details": safe_details,
        }
    )


__all__ = [
    "ProfilerConfig",
    "ProfilingHints",
    "SemanticHint",
    "profile_dataset",
]
