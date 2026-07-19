from __future__ import annotations

import json
import math
import re
import uuid
from collections.abc import Iterator, Mapping
from enum import StrEnum
from typing import Annotated, Any, ClassVar, TypeAlias, TypeVar, cast

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
    StringConstraints,
    GetCoreSchemaHandler,
    field_validator,
    model_validator,
)
from pydantic_core import CoreSchema, core_schema

T = TypeVar("T")

_LOCAL_PATH_PATTERN = re.compile(r"(?:/[A-Za-z0-9._ -]+){2,}|[A-Za-z]:[\\/][^\s]+|\\\\[^\s]+")
_SECRET_PATTERN = re.compile(
    r"(?i)(?:bearer\s+\S+|sk-[A-Za-z0-9_-]{8,}|(?:api[_-]?key|token|secret|password)\s*[:=]\s*\S+)"
)


def _as_tuple(value: object) -> object:
    if isinstance(value, list):
        return tuple(value)
    return value


def _unique_tuple(value: tuple[T, ...]) -> tuple[T, ...]:
    for position, item in enumerate(value):
        if item in value[:position]:
            raise ValueError("array entries must be unique")
    return value


def _finite_number(value: object) -> object:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("value must be a JSON number")
    if not math.isfinite(value):
        raise ValueError("number must be finite")
    return value


ImmutableTuple: TypeAlias = Annotated[tuple[T, ...], BeforeValidator(_as_tuple)]
UniqueTuple: TypeAlias = Annotated[
    tuple[T, ...], BeforeValidator(_as_tuple), AfterValidator(_unique_tuple)
]
FiniteNumber: TypeAlias = Annotated[int | float, BeforeValidator(_finite_number)]
LimitedString32: TypeAlias = Annotated[str, StringConstraints(max_length=32)]
LimitedString50: TypeAlias = Annotated[str, StringConstraints(max_length=50)]
LimitedString100: TypeAlias = Annotated[str, StringConstraints(max_length=100)]
LimitedString128: TypeAlias = Annotated[str, StringConstraints(max_length=128)]
LimitedString200: TypeAlias = Annotated[str, StringConstraints(max_length=200)]
LimitedString300: TypeAlias = Annotated[str, StringConstraints(max_length=300)]
LimitedString500: TypeAlias = Annotated[str, StringConstraints(max_length=500)]
LimitedString1000: TypeAlias = Annotated[str, StringConstraints(max_length=1000)]
LimitedString2000: TypeAlias = Annotated[str, StringConstraints(max_length=2000)]
LimitedString3000: TypeAlias = Annotated[str, StringConstraints(max_length=3000)]


class StrictStrEnum(StrEnum):
    """Enum that accepts JSON strings but rejects non-string coercion in strict models."""

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: object, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        del source_type, handler
        return core_schema.no_info_after_validator_function(
            cls,
            core_schema.str_schema(strict=True),
            serialization=core_schema.to_string_ser_schema(),
        )


class FrozenJsonObject(Mapping[str, object]):
    """Small immutable mapping used for intentionally open JSON objects."""

    __slots__ = ("_data",)

    def __init__(self, data: Mapping[str, object]) -> None:
        self._data = dict(data)

    def __getitem__(self, key: str) -> object:
        return self._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return f"FrozenJsonObject(keys={tuple(sorted(self._data))!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Mapping):
            return dict(self.items()) == dict(other.items())
        return False


def _freeze_json(value: object) -> object:
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(value):
            raise ValueError("JSON numbers must be finite")
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, object] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON object keys must be strings")
            frozen[key] = _freeze_json(child)
        return FrozenJsonObject(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(child) for child in value)
    raise ValueError("value is not JSON-safe")


def _freeze_json_object(value: object) -> FrozenJsonObject:
    frozen = _freeze_json(value)
    if not isinstance(frozen, FrozenJsonObject):
        raise ValueError("value must be a JSON object")
    return frozen


def _thaw_json(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude_unset=True)
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_thaw_json(child) for child in value]
    if isinstance(value, StrictStrEnum):
        return value.value
    if isinstance(value, str):
        return str(value)
    return value


def _reject_nonfinite_for_serialization(value: object) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("canonical JSON cannot contain non-finite numbers")
    if isinstance(value, BaseModel):
        for child in value.__dict__.values():
            _reject_nonfinite_for_serialization(child)
        return
    if isinstance(value, Mapping):
        for child in value.values():
            _reject_nonfinite_for_serialization(child)
        return
    if isinstance(value, (tuple, list)):
        for child in value:
            _reject_nonfinite_for_serialization(child)


JsonValue: TypeAlias = Annotated[
    Any,
    BeforeValidator(_freeze_json),
    PlainSerializer(_thaw_json, return_type=object, when_used="always"),
]
JsonObject: TypeAlias = Annotated[
    FrozenJsonObject,
    BeforeValidator(_freeze_json_object),
    PlainSerializer(_thaw_json, return_type=dict[str, object], when_used="always"),
]


def optional_field() -> Any:
    """Declare a schema-optional, non-null field without losing omission state."""

    return Field(default=None)


class CanonicalModel(BaseModel):
    """Strict immutable base with information-preserving canonical serialization."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        allow_inf_nan=False,
        hide_input_in_errors=True,
        arbitrary_types_allowed=True,
    )
    schema_logical_name: ClassVar[str | None] = None

    @model_validator(mode="before")
    @classmethod
    def _validate_canonical_schema(cls, value: object) -> object:
        if cls.schema_logical_name is None or isinstance(value, cls):
            return value
        native = _thaw_json(value)
        if not isinstance(native, dict):
            raise ValueError("canonical artifact must be a JSON object")
        _validate_against_registered_schema(cls.schema_logical_name, native)
        return value

    def to_canonical_dict(self) -> dict[str, object]:
        _reject_nonfinite_for_serialization(self)
        raw = self.model_dump(mode="json", exclude_unset=True)
        encoded = json.dumps(
            raw,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        result = json.loads(encoded)
        if not isinstance(result, dict):
            raise TypeError("canonical artifact serialization must produce an object")
        if self.schema_logical_name is not None:
            _validate_against_registered_schema(self.schema_logical_name, result)
        return cast(dict[str, object], result)

    def to_canonical_json(self) -> str:
        return json.dumps(
            self.to_canonical_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )


def _validate_against_registered_schema(logical_name: str, value: dict[str, object]) -> None:
    from riec_guard.contract.schema_loader import load_schema_registry

    schema = load_schema_registry().lookup(logical_name).validation_schema()
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    error = next(iter(validator.iter_errors(value)), None)
    if error is None:
        return
    location = ".".join(str(part) for part in error.absolute_path) or "root"
    raise ValueError(f"canonical schema validation failed at {location}")


class ErrorStage(StrictStrEnum):
    UPLOAD = "upload"
    PROFILE = "profile"
    CONTRACT = "contract"
    RIEC = "riec"
    PROTOCOL = "protocol"
    DECISION = "decision"
    GPT = "gpt"
    REPORT = "report"
    EXPORT = "export"
    RELEASE_SCAN = "release_scan"


class ErrorClass(StrictStrEnum):
    VALIDATION = "validation"
    SCALE_LIMIT = "scale_limit"
    DATA_QUALITY = "data_quality"
    FIT_FAILURE = "fit_failure"
    API_UNAVAILABLE = "api_unavailable"
    API_INVALID_OUTPUT = "api_invalid_output"
    PRIVACY_BLOCK = "privacy_block"
    SECURITY_BLOCK = "security_block"
    INTERNAL = "internal"


class _CompatibleEnvelopeCode(str):
    """Canonical uppercase value that still compares with legacy lowercase codes."""

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return str.__eq__(self, other) or self.lower() == other
        return False

    __hash__ = str.__hash__


ErrorId: TypeAlias = Annotated[str, StringConstraints(pattern=r"^ERR-[A-F0-9]{12}$")]
EnvelopeCode: TypeAlias = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")]


class ErrorEnvelope(CanonicalModel):
    """Canonical public error artifact with a legacy read-only details alias."""

    schema_logical_name = "error_envelope"

    schema_version: Annotated[str, StringConstraints(pattern=r"^1\.0\.0$")]
    error_id: ErrorId
    stage: ErrorStage
    error_class: ErrorClass
    code: EnvelopeCode
    message: LimitedString1000
    recoverable: bool
    user_action: LimitedString1000 | None
    safe_details: JsonObject
    cause_chain: Annotated[ImmutableTuple[LimitedString500], Field(max_length=10)] = (
        optional_field()
    )

    @field_validator("code")
    @classmethod
    def _legacy_code_comparison(cls, value: str) -> str:
        return _CompatibleEnvelopeCode(value)

    @property
    def details(self) -> dict[str, object] | None:
        """Compatibility view retained for TASK-003/004 callers."""

        details = cast(dict[str, object], _thaw_json(self.safe_details))
        return details or None

    @classmethod
    def from_exception(
        cls,
        error: BaseException,
        *,
        stage: ErrorStage = ErrorStage.REPORT,
    ) -> ErrorEnvelope:
        if isinstance(error, ApplicationError):
            return error.to_envelope()
        exception_name = type(error).__name__
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,99}", exception_name) is None:
            exception_name = "Exception"
        return cls.model_validate(
            {
                "schema_version": "1.0.0",
                "error_id": _new_error_id(),
                "stage": stage,
                "error_class": ErrorClass.INTERNAL,
                "code": "INTERNAL_ERROR",
                "message": "An internal error occurred.",
                "recoverable": False,
                "user_action": "Retry once; if the problem persists, report the safe error ID.",
                "safe_details": {},
                "cause_chain": (exception_name,),
            }
        )


class ErrorCode(StrictStrEnum):
    """Stable public error codes for guarded sources and ephemeral runs."""

    UNSUPPORTED_FILE_TYPE = "unsupported_file_type"
    ARCHIVE_UPLOAD_REJECTED = "archive_upload_rejected"
    UPLOAD_TOO_LARGE = "upload_too_large"
    TOO_MANY_ROWS = "too_many_rows"
    TOO_MANY_COLUMNS = "too_many_columns"
    MALFORMED_CSV = "malformed_csv"
    UNSAFE_DISPLAY_FILENAME = "unsafe_display_filename"
    BINARY_OR_NUL_CONTENT = "binary_or_nul_content"
    SOURCE_NOT_FOUND = "source_not_found"
    RUN_NOT_FOUND = "run_not_found"
    STORAGE_FAILURE = "storage_failure"
    CLEANUP_FAILURE = "cleanup_failure"


_ERROR_METADATA: dict[ErrorCode, tuple[ErrorStage, ErrorClass, bool, str | None]] = {
    ErrorCode.UNSUPPORTED_FILE_TYPE: (
        ErrorStage.UPLOAD,
        ErrorClass.SECURITY_BLOCK,
        True,
        "Upload a bounded UTF-8 CSV file.",
    ),
    ErrorCode.ARCHIVE_UPLOAD_REJECTED: (
        ErrorStage.UPLOAD,
        ErrorClass.SECURITY_BLOCK,
        True,
        "Upload an unarchived bounded UTF-8 CSV file.",
    ),
    ErrorCode.UPLOAD_TOO_LARGE: (
        ErrorStage.UPLOAD,
        ErrorClass.SECURITY_BLOCK,
        True,
        "Upload a smaller public CSV file.",
    ),
    ErrorCode.TOO_MANY_ROWS: (
        ErrorStage.UPLOAD,
        ErrorClass.SCALE_LIMIT,
        True,
        "Upload a public CSV within the documented row limit.",
    ),
    ErrorCode.TOO_MANY_COLUMNS: (
        ErrorStage.UPLOAD,
        ErrorClass.SCALE_LIMIT,
        True,
        "Upload a public CSV within the documented column limit.",
    ),
    ErrorCode.MALFORMED_CSV: (
        ErrorStage.UPLOAD,
        ErrorClass.VALIDATION,
        True,
        "Correct the CSV structure and upload it again.",
    ),
    ErrorCode.UNSAFE_DISPLAY_FILENAME: (
        ErrorStage.UPLOAD,
        ErrorClass.SECURITY_BLOCK,
        True,
        "Use a plain CSV filename without path or device syntax.",
    ),
    ErrorCode.BINARY_OR_NUL_CONTENT: (
        ErrorStage.UPLOAD,
        ErrorClass.SECURITY_BLOCK,
        True,
        "Upload UTF-8 or UTF-8-SIG CSV text without binary content.",
    ),
    ErrorCode.SOURCE_NOT_FOUND: (
        ErrorStage.PROFILE,
        ErrorClass.VALIDATION,
        True,
        "Select a source that belongs to the current run.",
    ),
    ErrorCode.RUN_NOT_FOUND: (
        ErrorStage.PROFILE,
        ErrorClass.VALIDATION,
        True,
        "Start a new run and select its source.",
    ),
    ErrorCode.STORAGE_FAILURE: (
        ErrorStage.UPLOAD,
        ErrorClass.INTERNAL,
        False,
        "Retry once; if the problem persists, start a new run.",
    ),
    ErrorCode.CLEANUP_FAILURE: (
        ErrorStage.EXPORT,
        ErrorClass.INTERNAL,
        False,
        "Retry cleanup without changing the configured runtime roots.",
    ),
}


class ApplicationError(RuntimeError):
    """Typed application failure whose public representation contains safe metadata only."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        field: str | None = None,
        source_id: str | None = None,
        run_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.field = field
        self.source_id = source_id
        self.run_id = run_id

    def to_envelope(self) -> ErrorEnvelope:
        stage, error_class, recoverable, user_action = _ERROR_METADATA[self.code]
        details = {
            key: _safe_detail_string(value)
            for key, value in (
                ("field", self.field),
                ("source_id", self.source_id),
                ("run_id", self.run_id),
            )
            if value is not None
        }
        return ErrorEnvelope.model_validate(
            {
                "schema_version": "1.0.0",
                "error_id": _new_error_id(),
                "stage": stage,
                "error_class": error_class,
                "code": self.code.name,
                "message": _safe_public_text(
                    self.message, fallback="The requested operation failed."
                ),
                "recoverable": recoverable,
                "user_action": user_action,
                "safe_details": details,
                "cause_chain": (),
            }
        )


def _new_error_id() -> str:
    return f"ERR-{uuid.uuid4().hex[:12].upper()}"


def _safe_public_text(value: object, *, fallback: str) -> str:
    if not isinstance(value, str) or not value:
        return fallback
    redacted = _LOCAL_PATH_PATTERN.sub("[redacted-path]", value)
    redacted = _SECRET_PATTERN.sub("[redacted-secret]", redacted)
    return redacted[:1000] or fallback


def _safe_detail_string(value: str) -> str:
    return _safe_public_text(value, fallback="[redacted]")[:500]


def error_envelope_from_exception(
    error: BaseException,
    *,
    stage: ErrorStage = ErrorStage.REPORT,
) -> ErrorEnvelope:
    return ErrorEnvelope.from_exception(error, stage=stage)


class FeatureNotImplementedError(RuntimeError):
    """Raised when a seed-only method is called before its scheduled task."""


__all__ = [
    "ApplicationError",
    "CanonicalModel",
    "ErrorClass",
    "ErrorCode",
    "ErrorEnvelope",
    "ErrorStage",
    "FeatureNotImplementedError",
    "FiniteNumber",
    "FrozenJsonObject",
    "ImmutableTuple",
    "JsonObject",
    "JsonValue",
    "LimitedString32",
    "LimitedString50",
    "LimitedString100",
    "LimitedString128",
    "LimitedString200",
    "LimitedString300",
    "LimitedString500",
    "LimitedString1000",
    "LimitedString2000",
    "LimitedString3000",
    "StrictStrEnum",
    "UniqueTuple",
    "error_envelope_from_exception",
    "optional_field",
]
