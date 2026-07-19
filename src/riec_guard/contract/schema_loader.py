from __future__ import annotations

import json
import re
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, cast

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from jsonschema.exceptions import (  # type: ignore[import-untyped]
    SchemaError,
    ValidationError,
)

SUPPORTED_INDEX_VERSION = "1.0.0"
EXPECTED_CANONICAL_COUNT = 11
EXPECTED_GPT_PROJECTION_COUNT = 3
MAX_JSON_BYTES = 5 * 1024 * 1024
_LOGICAL_NAME_PATTERN = re.compile(r"[a-z][a-z0-9_]{2,63}")
_SEMANTIC_VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class SchemaKind(str, Enum):
    CANONICAL = "canonical"
    GPT_PROJECTION = "gpt_projection"


class SchemaRegistryError(RuntimeError):
    """A stable, user-safe schema package failure."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class _DuplicateJsonKey(ValueError):
    pass


@dataclass(frozen=True)
class SchemaRecord:
    logical_name: str
    kind: SchemaKind
    schema_path: PurePosixPath
    example_path: PurePosixPath
    schema_version: str
    purpose: str
    promotes_to: str | None
    _schema_json: str
    _example_json: str

    def schema(self) -> dict[str, Any]:
        """Return a defensive copy of the registered schema or GPT wrapper."""

        return cast(dict[str, Any], json.loads(self._schema_json))

    def example(self) -> dict[str, Any]:
        """Return a defensive copy of the registered example."""

        return cast(dict[str, Any], json.loads(self._example_json))

    def validation_schema(self) -> dict[str, Any]:
        """Return the canonical schema or the inner GPT transport schema."""

        schema = self.schema()
        if self.kind is SchemaKind.GPT_PROJECTION:
            return cast(dict[str, Any], schema["schema"])
        return schema


class SchemaRegistry:
    """Immutable registry view backed by serialized, mutation-safe JSON values."""

    def __init__(self, *, index_version: str, records: tuple[SchemaRecord, ...]) -> None:
        self._index_version = index_version
        self._records = records
        self._by_name = {record.logical_name: record for record in records}

    @property
    def index_version(self) -> str:
        return self._index_version

    def lookup(self, logical_name: str) -> SchemaRecord:
        try:
            return self._by_name[logical_name]
        except KeyError as exc:
            raise SchemaRegistryError(
                "SCHEMA_NOT_REGISTERED", "requested logical schema name is not registered"
            ) from exc

    def canonical(self) -> tuple[SchemaRecord, ...]:
        return tuple(record for record in self._records if record.kind is SchemaKind.CANONICAL)

    def gpt_projections(self) -> tuple[SchemaRecord, ...]:
        return tuple(record for record in self._records if record.kind is SchemaKind.GPT_PROJECTION)

    def promotion_target(self, logical_name: str) -> SchemaRecord:
        projection = self.lookup(logical_name)
        if projection.kind is not SchemaKind.GPT_PROJECTION or projection.promotes_to is None:
            raise SchemaRegistryError(
                "GPT_PROMOTION_NOT_AVAILABLE",
                "requested schema is not a GPT projection with a promotion target",
            )
        return self.lookup(projection.promotes_to)


def _raise(code: str, message: str) -> NoReturn:
    raise SchemaRegistryError(code, message)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def _read_json(path: Path, *, code: str, label: str) -> dict[str, Any]:
    try:
        metadata = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_JSON_BYTES:
            _raise(code, f"{label} is not a safe bounded JSON file")
        raw = path.read_text(encoding="utf-8")
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except SchemaRegistryError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, _DuplicateJsonKey) as exc:
        raise SchemaRegistryError(code, f"{label} is missing, unreadable, or malformed") from exc
    if not isinstance(value, dict):
        _raise(code, f"{label} must contain one JSON object")
    return value


def _require_exact_keys(
    value: dict[str, Any], required: set[str], *, code: str, label: str
) -> None:
    if set(value) != required:
        _raise(code, f"{label} has missing or unsupported fields")


def _required_string(value: object, *, code: str, label: str) -> str:
    if not isinstance(value, str) or not value:
        _raise(code, f"{label} must be a non-empty string")
    return value


def _safe_registered_path(
    repository_root: Path,
    schema_root: Path,
    raw_path: object,
    *,
    label: str,
) -> tuple[PurePosixPath, Path]:
    path_text = _required_string(raw_path, code="INDEX_PATH_INVALID", label=label)
    if "\\" in path_text:
        _raise("INDEX_PATH_INVALID", f"{label} must use a normalized repository-relative path")
    relative = PurePosixPath(path_text)
    if (
        relative.is_absolute()
        or path_text != relative.as_posix()
        or "." in relative.parts
        or ".." in relative.parts
        or not relative.parts
        or relative.parts[0] != "schemas"
    ):
        _raise("INDEX_PATH_INVALID", f"{label} must remain under the repository schema root")

    candidate = repository_root.joinpath(*relative.parts)
    current = repository_root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            _raise("INDEX_PATH_ESCAPE", f"{label} contains a symbolic-link component")
        if not current.exists():
            break
    try:
        resolved = candidate.resolve(strict=False)
    except OSError as exc:
        raise SchemaRegistryError(
            "INDEX_PATH_ESCAPE", f"{label} cannot be safely resolved"
        ) from exc
    if not resolved.is_relative_to(schema_root):
        _raise("INDEX_PATH_ESCAPE", f"{label} resolves outside the repository schema root")
    return relative, candidate


def _serialized(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _reject_remote_refs(value: object, logical_name: str) -> None:
    if isinstance(value, dict):
        reference = value.get("$ref")
        if isinstance(reference, str) and not reference.startswith("#"):
            _raise(
                "REMOTE_REF_FORBIDDEN",
                f"registered schema {logical_name} contains a non-local reference",
            )
        for child in value.values():
            _reject_remote_refs(child, logical_name)
    elif isinstance(value, list):
        for child in value:
            _reject_remote_refs(child, logical_name)


def _validate_gpt_wrapper(wrapper: dict[str, Any], logical_name: str) -> dict[str, Any]:
    if set(wrapper) != {"$schema", "name", "strict", "schema"}:
        _raise(
            "GPT_WRAPPER_INVALID",
            f"GPT projection {logical_name} has an invalid wrapper structure",
        )
    if (
        wrapper.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
        or not isinstance(wrapper.get("name"), str)
        or not wrapper.get("name")
        or wrapper.get("strict") is not True
        or not isinstance(wrapper.get("schema"), dict)
    ):
        _raise(
            "GPT_WRAPPER_INVALID",
            f"GPT projection {logical_name} has invalid wrapper metadata",
        )
    return cast(dict[str, Any], wrapper["schema"])


def _check_schema(schema: dict[str, Any], logical_name: str, *, gpt: bool) -> None:
    _reject_remote_refs(schema, logical_name)
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        kind = "GPT projection" if gpt else "canonical schema"
        raise SchemaRegistryError(
            "SCHEMA_DEFINITION_INVALID", f"{kind} {logical_name} is not valid Draft 2020-12"
        ) from exc


def _validate_example(
    schema: dict[str, Any], example: dict[str, Any], logical_name: str, *, gpt: bool
) -> None:
    try:
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(example)
    except ValidationError as exc:
        kind = "GPT projection" if gpt else "canonical schema"
        raise SchemaRegistryError(
            "SCHEMA_EXAMPLE_INVALID", f"example for {kind} {logical_name} is invalid"
        ) from exc


def _load_schema_registry(repository_root: Path) -> SchemaRegistry:
    try:
        resolved_repository_root = repository_root.resolve(strict=True)
        schema_root = (resolved_repository_root / "schemas").resolve(strict=True)
    except OSError as exc:
        raise SchemaRegistryError(
            "SCHEMA_ROOT_INVALID", "repository schema root is missing or unsafe"
        ) from exc
    if not schema_root.is_dir() or not schema_root.is_relative_to(resolved_repository_root):
        _raise("SCHEMA_ROOT_INVALID", "repository schema root is missing or unsafe")
    index_path = schema_root / "SCHEMA_INDEX.json"
    if index_path.is_symlink():
        _raise("INDEX_PATH_ESCAPE", "schema index must not be a symbolic link")
    index = _read_json(index_path, code="SCHEMA_INDEX_INVALID", label="schema index")
    _require_exact_keys(
        index,
        {"index_version", "phase", "architecture_version", "entries", "notes"},
        code="SCHEMA_INDEX_INVALID",
        label="schema index",
    )
    if index["index_version"] != SUPPORTED_INDEX_VERSION:
        _raise("INDEX_VERSION_UNSUPPORTED", "schema index version is unsupported")
    if index["phase"] != "D" or not isinstance(index["architecture_version"], str):
        _raise("SCHEMA_INDEX_INVALID", "schema index metadata is invalid")
    if not isinstance(index["notes"], list) or not all(
        isinstance(note, str) for note in index["notes"]
    ):
        _raise("SCHEMA_INDEX_INVALID", "schema index notes are invalid")
    raw_entries = index["entries"]
    if not isinstance(raw_entries, list):
        _raise("SCHEMA_INDEX_INVALID", "schema index entries must be a list")

    parsed: list[
        tuple[
            str,
            SchemaKind,
            PurePosixPath,
            Path,
            PurePosixPath,
            Path,
            str,
            str,
            str | None,
        ]
    ] = []
    names: set[str] = set()
    schema_paths: set[PurePosixPath] = set()
    example_paths: set[PurePosixPath] = set()

    for position, raw_entry in enumerate(raw_entries):
        label = f"schema index entry {position + 1}"
        if not isinstance(raw_entry, dict):
            _raise("INDEX_ENTRY_INVALID", f"{label} must be an object")
        entry = cast(dict[str, Any], raw_entry)
        common_keys = {
            "logical_name",
            "kind",
            "schema_path",
            "example_path",
            "schema_version",
            "purpose",
        }
        raw_kind = entry.get("kind")
        if raw_kind == SchemaKind.CANONICAL.value:
            kind = SchemaKind.CANONICAL
            _require_exact_keys(entry, common_keys, code="INDEX_ENTRY_INVALID", label=label)
        elif raw_kind == SchemaKind.GPT_PROJECTION.value:
            kind = SchemaKind.GPT_PROJECTION
            if "promotes_to" not in entry:
                _raise("GPT_PROMOTION_MISSING", f"{label} has no canonical promotion target")
            _require_exact_keys(
                entry,
                common_keys | {"promotes_to"},
                code="INDEX_ENTRY_INVALID",
                label=label,
            )
        else:
            _raise("SCHEMA_KIND_UNKNOWN", f"{label} has an unknown schema kind")

        logical_name = _required_string(
            entry["logical_name"], code="INDEX_ENTRY_INVALID", label=f"{label} logical_name"
        )
        if _LOGICAL_NAME_PATTERN.fullmatch(logical_name) is None:
            _raise("INDEX_ENTRY_INVALID", f"{label} logical_name is invalid")
        if logical_name in names:
            _raise("DUPLICATE_LOGICAL_NAME", "schema index contains a duplicate logical name")
        names.add(logical_name)

        schema_path, schema_file = _safe_registered_path(
            resolved_repository_root,
            schema_root,
            entry["schema_path"],
            label=f"{label} schema_path",
        )
        if schema_path in schema_paths:
            _raise("DUPLICATE_SCHEMA_PATH", "schema index contains a duplicate schema path")
        schema_paths.add(schema_path)

        example_path, example_file = _safe_registered_path(
            resolved_repository_root,
            schema_root,
            entry["example_path"],
            label=f"{label} example_path",
        )
        if example_path in example_paths:
            _raise("DUPLICATE_EXAMPLE_PATH", "schema index contains a duplicate example path")
        example_paths.add(example_path)

        schema_version = _required_string(
            entry["schema_version"],
            code="INDEX_ENTRY_INVALID",
            label=f"{label} schema_version",
        )
        if _SEMANTIC_VERSION_PATTERN.fullmatch(schema_version) is None:
            _raise("INDEX_ENTRY_INVALID", f"{label} schema_version is invalid")
        purpose = _required_string(
            entry["purpose"], code="INDEX_ENTRY_INVALID", label=f"{label} purpose"
        )
        promotes_to: str | None = None
        if kind is SchemaKind.GPT_PROJECTION:
            promotes_to = _required_string(
                entry["promotes_to"],
                code="GPT_PROMOTION_MISSING",
                label=f"{label} promotes_to",
            )
        parsed.append(
            (
                logical_name,
                kind,
                schema_path,
                schema_file,
                example_path,
                example_file,
                schema_version,
                purpose,
                promotes_to,
            )
        )

    canonical_count = sum(1 for item in parsed if item[1] is SchemaKind.CANONICAL)
    gpt_count = sum(1 for item in parsed if item[1] is SchemaKind.GPT_PROJECTION)
    if canonical_count != EXPECTED_CANONICAL_COUNT or gpt_count != EXPECTED_GPT_PROJECTION_COUNT:
        _raise(
            "INDEX_COUNT_MISMATCH",
            "schema index must register exactly 11 canonical and 3 GPT projection schemas",
        )

    records: list[SchemaRecord] = []
    canonical_ids: set[str] = set()
    for (
        logical_name,
        kind,
        schema_path,
        schema_file,
        example_path,
        example_file,
        schema_version,
        purpose,
        promotes_to,
    ) in parsed:
        if not schema_file.is_file():
            _raise("SCHEMA_FILE_MISSING", f"registered schema {logical_name} is missing")
        if not example_file.is_file():
            _raise("SCHEMA_EXAMPLE_MISSING", f"example for schema {logical_name} is missing")
        schema_value = _read_json(
            schema_file, code="SCHEMA_JSON_INVALID", label=f"schema {logical_name}"
        )
        example_value = _read_json(
            example_file,
            code="SCHEMA_EXAMPLE_JSON_INVALID",
            label=f"example for schema {logical_name}",
        )

        if kind is SchemaKind.CANONICAL:
            schema_id = schema_value.get("$id")
            if isinstance(schema_id, str):
                if schema_id in canonical_ids:
                    _raise("DUPLICATE_SCHEMA_ID", "canonical schemas contain a duplicate $id")
                canonical_ids.add(schema_id)
            properties = schema_value.get("properties")
            version_definition = (
                properties.get("schema_version") if isinstance(properties, dict) else None
            )
            schema_const = (
                version_definition.get("const") if isinstance(version_definition, dict) else None
            )
            if schema_const != schema_version:
                _raise(
                    "CANONICAL_VERSION_MISMATCH",
                    f"canonical schema {logical_name} does not match its indexed version",
                )
            if example_value.get("schema_version") != schema_const:
                _raise(
                    "CANONICAL_EXAMPLE_VERSION_MISMATCH",
                    f"example for canonical schema {logical_name} has a mismatched version",
                )
            validation_schema = schema_value
        else:
            validation_schema = _validate_gpt_wrapper(schema_value, logical_name)

        _check_schema(
            validation_schema,
            logical_name,
            gpt=kind is SchemaKind.GPT_PROJECTION,
        )
        _validate_example(
            validation_schema,
            example_value,
            logical_name,
            gpt=kind is SchemaKind.GPT_PROJECTION,
        )
        records.append(
            SchemaRecord(
                logical_name=logical_name,
                kind=kind,
                schema_path=schema_path,
                example_path=example_path,
                schema_version=schema_version,
                purpose=purpose,
                promotes_to=promotes_to,
                _schema_json=_serialized(schema_value),
                _example_json=_serialized(example_value),
            )
        )

    by_name = {record.logical_name: record for record in records}
    for record in records:
        if record.kind is not SchemaKind.GPT_PROJECTION:
            continue
        if record.promotes_to is None or record.promotes_to not in by_name:
            _raise(
                "GPT_PROMOTION_TARGET_INVALID",
                f"GPT projection {record.logical_name} has an unknown promotion target",
            )
        if by_name[record.promotes_to].kind is not SchemaKind.CANONICAL:
            _raise(
                "GPT_PROMOTION_TARGET_INVALID",
                f"GPT projection {record.logical_name} must promote to a canonical schema",
            )

    return SchemaRegistry(index_version=SUPPORTED_INDEX_VERSION, records=tuple(records))


def load_schema_registry() -> SchemaRegistry:
    """Load and validate the repository-owned schema package.

    The production API intentionally accepts no filesystem path. Tests replace the private
    repository-root constant so malformed synthetic packages can be exercised in temporary
    directories. No registry cache is used; records retain immutable serialized JSON and return
    a new object for every schema/example access.
    """

    return _load_schema_registry(_REPOSITORY_ROOT)


__all__ = [
    "SchemaKind",
    "SchemaRecord",
    "SchemaRegistry",
    "SchemaRegistryError",
    "load_schema_registry",
]
