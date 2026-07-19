from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping
from copy import deepcopy
from types import MappingProxyType
from typing import Any, NoReturn, cast

from pydantic import ValidationError

from riec_guard.contract.models import AuditContract, ContractIdentity

_PLACEHOLDER_CONTRACT_ID = "AC-000000000000"
_SCHEMA_LOCATION_PATTERN = re.compile(r"canonical schema validation failed at ([A-Za-z0-9_.]+)")

CANONICAL_UNIT_ALIASES = MappingProxyType(
    {
        "mL": (
            "mL",
            "ml",
            "milliliter",
            "milliliters",
            "millilitre",
            "millilitres",
        ),
        "L": ("L", "l", "liter", "liters", "litre", "litres"),
        "uL": (
            "uL",
            "ul",
            "µL",
            "μL",
            "microliter",
            "microliters",
            "microlitre",
            "microlitres",
        ),
        "g": ("g", "gram", "grams"),
        "kg": ("kg", "kilogram", "kilograms"),
        "mg": ("mg", "milligram", "milligrams"),
    }
)

CONFIRMATION_FIELD_ORDER = (
    "column_mapping.quantity.column",
    "column_mapping.deployment_group.column",
    "measurement.quantity_semantics",
    "measurement.unit",
    "grouping.deployment_group_columns",
    "ordering.status",
    "ordering.time_column",
    "policy.nominal_quantity",
    "policy.lower_limit",
    "policy.alpha",
    "policy.minimum_actionable_shift",
    "policy.maximum_screening_shift",
    "policy.protocol_spread_tolerance",
    "riec.c",
    "privacy.classification",
)
_CONFIRMATION_FIELD_POSITIONS = {
    field: position for position, field in enumerate(CONFIRMATION_FIELD_ORDER)
}


def _unit_key(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).strip().replace("μ", "u").replace("µ", "u")
    return normalized.casefold()


_UNIT_LOOKUP = MappingProxyType(
    {
        _unit_key(alias): canonical
        for canonical, aliases in CANONICAL_UNIT_ALIASES.items()
        for alias in aliases
    }
)


class ContractCanonicalizationError(ValueError):
    """Safe, value-redacted failure at the contract representation boundary."""

    code = "CONTRACT_SCHEMA_INVALID"

    def __init__(self, message: str, *, field_path: str = "root") -> None:
        super().__init__(message)
        self.field_path = field_path[:200] or "root"


def normalize_unit(value: str) -> str | None:
    """Return one frozen canonical Fill Pack unit spelling, or None for an unknown unit."""

    if not isinstance(value, str):
        return None
    return _UNIT_LOOKUP.get(_unit_key(value))


def canonicalize_confirmation_fields(fields: object) -> tuple[str, ...]:
    """Canonicalize the explicitly set-like confirmation paths in frozen semantic order."""

    if not isinstance(fields, (list, tuple, set, frozenset)) or not all(
        isinstance(field, str) for field in fields
    ):
        raise ContractCanonicalizationError(
            "Confirmation fields must be a collection of strings.",
            field_path="confirmation.confirmed_fields",
        )
    normalized = {unicodedata.normalize("NFKC", field).strip() for field in fields}
    return tuple(
        sorted(
            normalized,
            key=lambda field: (
                _CONFIRMATION_FIELD_POSITIONS.get(field, len(CONFIRMATION_FIELD_ORDER)),
                field,
            ),
        )
    )


def canonicalize_audit_contract(
    payload: AuditContract | Mapping[str, object],
) -> AuditContract:
    """Normalize representation and recompute identity without inventing contract semantics."""

    normalized = _as_mutable_contract(payload)
    _normalize_contract_representation(normalized)
    normalized["contract_id"] = _PLACEHOLDER_CONTRACT_ID
    provisional = _model_validate(normalized)
    identity = compute_contract_hash(provisional)
    normalized["contract_id"] = identity.contract_id
    return _model_validate(normalized)


def compute_contract_hash(contract: AuditContract) -> ContractIdentity:
    """Apply the frozen exclusion/serialization algorithm and derive the canonical contract ID."""

    value = contract.to_canonical_dict()
    value.pop("contract_id", None)
    value.pop("created_at", None)
    compiler = value.get("compiler")
    if isinstance(compiler, dict):
        compiler.pop("request_id", None)
    confirmation = value.get("confirmation")
    if isinstance(confirmation, dict):
        confirmation.pop("confirmed_at", None)
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    return ContractIdentity.model_validate(
        {
            "canonical_contract_sha256": digest,
            "contract_id": f"AC-{digest[:12].upper()}",
        }
    )


def _as_mutable_contract(payload: AuditContract | Mapping[str, object]) -> dict[str, Any]:
    if isinstance(payload, AuditContract):
        return cast(dict[str, Any], deepcopy(payload.to_canonical_dict()))
    if not isinstance(payload, Mapping):
        raise ContractCanonicalizationError("Contract payload must be a JSON object.")
    try:
        value = _copy_json_value(payload)
        json.dumps(value, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        raise ContractCanonicalizationError(
            "Contract payload contains a non-JSON or non-finite value."
        ) from None
    if not isinstance(value, dict):
        raise ContractCanonicalizationError("Contract payload must be a JSON object.")
    return value


def _copy_json_value(value: object) -> Any:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise TypeError("JSON object keys must be strings")
            result[key] = _copy_json_value(child)
        return result
    if isinstance(value, (list, tuple)):
        return [_copy_json_value(child) for child in value]
    raise TypeError("value is not JSON-compatible")


def _normalize_contract_representation(contract: dict[str, Any]) -> None:
    normalized = _normalize_unicode(contract)
    contract.clear()
    contract.update(cast(dict[str, Any], normalized))

    for path in (
        ("created_at",),
        ("compiler", "model"),
        ("compiler", "structured_output_schema_version"),
        ("compiler", "request_id"),
        ("source", "dataset_id"),
        ("source", "dataset_sha256"),
        ("grouping", "deployment_unit_name"),
        ("ordering", "time_column"),
        ("ordering", "timezone"),
        ("policy", "policy_source", "title"),
        ("policy", "policy_source", "text_sha256"),
        ("evidence_profile", "profile_version"),
        ("riec", "candidate_registry_id"),
        ("confirmation", "confirmed_at"),
    ):
        _trim_string_at(contract, path)

    mapping = contract.get("column_mapping")
    if isinstance(mapping, dict):
        for reference in mapping.values():
            if isinstance(reference, dict) and isinstance(reference.get("column"), str):
                reference["column"] = reference["column"].strip()

    measurement = contract.get("measurement")
    if isinstance(measurement, dict) and isinstance(measurement.get("unit"), str):
        unit = measurement["unit"].strip()
        measurement["unit"] = normalize_unit(unit) or unit

    grouping = contract.get("grouping")
    if isinstance(grouping, dict):
        _trim_string_list(grouping, "deployment_group_columns")
        _trim_string_list(grouping, "nested_context_columns")

    ordering = contract.get("ordering")
    if isinstance(ordering, dict):
        _trim_string_list(ordering, "tie_break_columns")

    unresolved = contract.get("unresolved_fields")
    if isinstance(unresolved, list):
        for item in unresolved:
            if isinstance(item, dict):
                for key in ("field_path", "question"):
                    if isinstance(item.get(key), str):
                        item[key] = item[key].strip()
        _reject_duplicate_records(unresolved, "unresolved_fields")
        unresolved.sort(
            key=lambda item: (
                item.get("severity", "") if isinstance(item, dict) else "",
                item.get("field_path", "") if isinstance(item, dict) else "",
                item.get("question", "") if isinstance(item, dict) else "",
            )
        )

    assumptions = contract.get("assumptions")
    if isinstance(assumptions, list):
        seen_ids: set[str] = set()
        for item in assumptions:
            if not isinstance(item, dict):
                continue
            for key in ("assumption_id", "text"):
                if isinstance(item.get(key), str):
                    item[key] = item[key].strip()
            assumption_id = item.get("assumption_id")
            if isinstance(assumption_id, str):
                if assumption_id in seen_ids:
                    _fail("Duplicate normalized assumption IDs are not allowed.", "assumptions")
                seen_ids.add(assumption_id)
        assumptions.sort(
            key=lambda item: item.get("assumption_id", "") if isinstance(item, dict) else ""
        )

    confirmation = contract.get("confirmation")
    if isinstance(confirmation, dict):
        confirmed_fields = confirmation.get("confirmed_fields")
        if isinstance(confirmed_fields, list):
            confirmation["confirmed_fields"] = canonicalize_confirmation_fields(confirmed_fields)


def _normalize_unicode(value: object) -> object:
    if isinstance(value, str):
        return unicodedata.normalize("NFKC", value)
    if isinstance(value, dict):
        return {key: _normalize_unicode(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_normalize_unicode(child) for child in value]
    return value


def _trim_string_at(root: dict[str, Any], path: tuple[str, ...]) -> None:
    current: Any = root
    for part in path[:-1]:
        if not isinstance(current, dict):
            return
        current = current.get(part)
    if isinstance(current, dict) and isinstance(current.get(path[-1]), str):
        current[path[-1]] = current[path[-1]].strip()


def _trim_string_list(parent: dict[str, Any], key: str) -> None:
    values = parent.get(key)
    if isinstance(values, list):
        parent[key] = [value.strip() if isinstance(value, str) else value for value in values]


def _reject_duplicate_records(records: list[Any], field_path: str) -> None:
    encoded: set[str] = set()
    for record in records:
        fingerprint = json.dumps(
            record, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        if fingerprint in encoded:
            _fail("Duplicate normalized records are not allowed.", field_path)
        encoded.add(fingerprint)


def _model_validate(payload: dict[str, Any]) -> AuditContract:
    try:
        return AuditContract.model_validate(payload)
    except ValidationError as error:
        field_path = _validation_field_path(error)
        raise ContractCanonicalizationError(
            "Contract payload does not satisfy the canonical contract schema.",
            field_path=field_path,
        ) from None


def _validation_field_path(error: ValidationError) -> str:
    for detail in error.errors(include_input=False):
        message = str(detail.get("msg", ""))
        match = _SCHEMA_LOCATION_PATTERN.search(message)
        if match is not None:
            return match.group(1)
        location = detail.get("loc")
        if isinstance(location, tuple) and location:
            return ".".join(str(part) for part in location)
    return "root"


def _fail(message: str, field_path: str) -> NoReturn:
    raise ContractCanonicalizationError(message, field_path=field_path)


__all__ = [
    "CANONICAL_UNIT_ALIASES",
    "CONFIRMATION_FIELD_ORDER",
    "ContractCanonicalizationError",
    "canonicalize_audit_contract",
    "canonicalize_confirmation_fields",
    "compute_contract_hash",
    "normalize_unit",
]
