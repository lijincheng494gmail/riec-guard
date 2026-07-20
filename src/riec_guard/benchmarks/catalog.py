"""Deterministic public catalog and JSON-asset helpers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import TypeVar, cast

from riec_guard.benchmarks.models import (
    SCENARIO_ORDER,
    DemoBenchmarkSummary,
    RecordedScenarioSummary,
    ScenarioCatalog,
)
from riec_guard.benchmarks.scenarios import scenario_definitions, shared_design, shared_policy
from riec_guard.errors import CanonicalModel

CanonicalT = TypeVar("CanonicalT", bound=CanonicalModel)


class DuplicateJsonKeyError(ValueError):
    """Raised when a public JSON asset contains an ambiguous object."""


def canonical_sha256(value: object) -> str:
    """Hash finite JSON using the repository canonical encoding."""

    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def json_asset_bytes(model: CanonicalModel) -> bytes:
    """Render one human-readable but byte-stable public JSON asset."""

    return (
        json.dumps(
            model.to_canonical_dict(),
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def parse_json_object(data: bytes) -> dict[str, object]:
    """Strictly parse one UTF-8 finite JSON object and reject duplicate keys."""

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise DuplicateJsonKeyError("duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        del value
        raise ValueError("non-finite JSON number")

    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateJsonKeyError, ValueError):
        raise ValueError("public JSON asset is invalid") from None
    if not isinstance(value, dict):
        raise ValueError("public JSON asset must be an object")
    return cast(dict[str, object], value)


def hash_without_field(payload: Mapping[str, object], field: str) -> str:
    value = dict(payload)
    value.pop(field, None)
    return canonical_sha256(value)


def build_scenario_catalog() -> ScenarioCatalog:
    """Return the one fixed, public-safe three-scenario catalog."""

    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "catalog_id": "riec-guard-public-scenarios.v1",
        "catalog_version": "1.0.0",
        "fixed_order": SCENARIO_ORDER,
        "shared_design": shared_design(),
        "shared_policy": shared_policy(),
        "scenarios": scenario_definitions(),
        "classification": "public_synthetic",
        "purpose": (
            "Three deterministic synthetic mechanism demonstrations for reproducible RIEC "
            "Guard software behavior."
        ),
        "limitations": (
            "These scenarios do not establish performance in a real production facility.",
            "Recorded results are not evidence of achieved savings.",
            "Recorded results are not a compliance determination.",
            "The gallery does not establish universal validation.",
        ),
        "content_sha256": "0" * 64,
    }
    provisional = ScenarioCatalog.model_validate(payload)
    payload["content_sha256"] = hash_without_field(
        provisional.to_canonical_dict(),
        "content_sha256",
    )
    return ScenarioCatalog.model_validate(payload)


def validate_catalog_identity(catalog: ScenarioCatalog) -> None:
    """Fail closed if order, definitions, policy, or self-hash drifted."""

    expected = build_scenario_catalog()
    if catalog.to_canonical_dict() != expected.to_canonical_dict():
        raise ValueError("scenario catalog does not match the fixed public registry")
    actual = hash_without_field(catalog.to_canonical_dict(), "content_sha256")
    if actual != catalog.content_sha256:
        raise ValueError("scenario catalog content hash is invalid")


def seal_record(payload: Mapping[str, object]) -> RecordedScenarioSummary:
    """Validate and self-hash one deterministic run-neutral display record."""

    value = dict(payload)
    value["record_sha256"] = "0" * 64
    provisional = RecordedScenarioSummary.model_validate(value)
    value["record_sha256"] = hash_without_field(
        provisional.to_canonical_dict(),
        "record_sha256",
    )
    return RecordedScenarioSummary.model_validate(value)


def validate_record_identity(record: RecordedScenarioSummary) -> None:
    actual = hash_without_field(record.to_canonical_dict(), "record_sha256")
    if actual != record.record_sha256:
        raise ValueError("scenario record content hash is invalid")


def seal_benchmark_summary(
    records: tuple[RecordedScenarioSummary, ...],
    *,
    catalog_sha256: str,
) -> DemoBenchmarkSummary:
    """Build the run-neutral recorded summary after real service execution."""

    if tuple(record.scenario_id for record in records) != SCENARIO_ORDER:
        raise ValueError("benchmark records must use the fixed scenario order")
    for record in records:
        validate_record_identity(record)
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "summary_id": "riec-guard-demo-benchmark.v1",
        "summary_version": "1.0.0",
        "artifact_classification": "recorded_deterministic_output",
        "generated_by": "accepted_production_default_service",
        "live_recomputation_on_check": False,
        "bootstrap_replicates": 200,
        "bootstrap_seed": 20260718,
        "shared_policy": shared_policy(),
        "catalog_sha256": catalog_sha256,
        "scenario_records_sha256": canonical_sha256(
            [record.to_canonical_dict() for record in records]
        ),
        "scenarios": records,
        "limitations": (
            "This file records deterministic outputs produced by the accepted production-default service.",
            "The fast asset check validates bytes, identities, and recorded metadata without live analysis.",
            "These synthetic results are not evidence of achieved factory savings.",
            "These synthetic results are not a compliance determination.",
            "The recorded gallery does not establish universal validation.",
        ),
        "content_sha256": "0" * 64,
    }
    provisional = DemoBenchmarkSummary.model_validate(payload)
    payload["content_sha256"] = hash_without_field(
        provisional.to_canonical_dict(),
        "content_sha256",
    )
    return DemoBenchmarkSummary.model_validate(payload)


def validate_benchmark_identity(
    summary: DemoBenchmarkSummary,
    *,
    catalog: ScenarioCatalog,
) -> None:
    """Validate every internal hash without invoking analytical services."""

    validate_catalog_identity(catalog)
    if summary.catalog_sha256 != catalog.content_sha256:
        raise ValueError("benchmark summary catalog hash is invalid")
    if tuple(record.scenario_id for record in summary.scenarios) != SCENARIO_ORDER:
        raise ValueError("benchmark summary scenario order is invalid")
    for record in summary.scenarios:
        validate_record_identity(record)
    records_hash = canonical_sha256([record.to_canonical_dict() for record in summary.scenarios])
    if summary.scenario_records_sha256 != records_hash:
        raise ValueError("benchmark scenario-record hash is invalid")
    actual = hash_without_field(summary.to_canonical_dict(), "content_sha256")
    if summary.content_sha256 != actual:
        raise ValueError("benchmark summary content hash is invalid")


__all__ = [
    "build_scenario_catalog",
    "canonical_sha256",
    "hash_without_field",
    "json_asset_bytes",
    "parse_json_object",
    "seal_benchmark_summary",
    "seal_record",
    "validate_benchmark_identity",
    "validate_catalog_identity",
    "validate_record_identity",
]
