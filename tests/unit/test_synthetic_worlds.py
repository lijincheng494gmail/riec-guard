from __future__ import annotations

import csv
import hashlib
import io
import math
import re
from collections import Counter, defaultdict
from dataclasses import FrozenInstanceError
from datetime import datetime
from itertools import pairwise
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from riec_guard.benchmarks.catalog import (
    build_scenario_catalog,
    json_asset_bytes,
    parse_json_object,
    validate_catalog_identity,
)
from riec_guard.benchmarks.models import (
    SCENARIO_ORDER,
    PublicClassification,
    ScenarioDefinition,
    ScenarioId,
    SharedPolicyProfile,
    SharedScenarioDesign,
)
from riec_guard.benchmarks.scenarios import (
    generate_scenario,
    generate_scenario_csv,
    get_scenario_definition,
    scenario_definitions,
    shared_design,
    shared_policy,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_HEADER = (
    "quantity",
    "product",
    "batch_id",
    "timestamp",
    "stream",
    "shift",
    "row_sequence",
)
TWO_DECIMAL_QUANTITY = re.compile(r"^[0-9]+\.[0-9]{2}$")


def _rows(csv_bytes: bytes) -> tuple[dict[str, str], ...]:
    text = csv_bytes.decode("utf-8")
    assert text.endswith("\n")
    assert "\r" not in text
    reader = csv.DictReader(io.StringIO(text, newline=""))
    assert tuple(reader.fieldnames or ()) == EXPECTED_HEADER
    parsed = tuple(reader)
    assert all(
        None not in row and all(value is not None for value in row.values()) for row in parsed
    )
    return cast(tuple[dict[str, str], ...], parsed)


def test_catalog_has_exact_frozen_order_design_and_policy() -> None:
    definitions = scenario_definitions()

    assert len(definitions) == 3
    assert (
        tuple(definition.scenario_id for definition in definitions)
        == SCENARIO_ORDER
        == (
            ScenarioId.STABLE_SYMMETRIC,
            ScenarioId.HEAVY_TAIL_PARTICULATE,
            ScenarioId.BATCH_DRIFT_CHANGE_POINT,
        )
    )
    assert tuple(definition.scenario_version for definition in definitions) == (
        "1.0.0",
        "1.0.0",
        "1.0.0",
    )

    design = shared_design()
    assert design.deployment_group_count == 12
    assert design.rows_per_group == 88
    assert design.row_count == 1056
    assert design.rows_per_product == 528
    assert design.expected_tail_count_per_product == 5.28
    assert design.rows_per_product * shared_policy().alpha == 5.28

    policy = shared_policy()
    assert policy.alpha == 0.01
    assert policy.min_expected_tail_count == 5
    assert policy.bootstrap_replicates == 200
    assert policy.bootstrap_seed == 20260718
    assert all(definition.design == design for definition in definitions)
    assert all(definition.policy == policy for definition in definitions)


@pytest.mark.parametrize("scenario_id", SCENARIO_ORDER, ids=lambda item: item.value)
def test_generated_world_has_exact_balanced_geometry(scenario_id: ScenarioId) -> None:
    rows = _rows(generate_scenario_csv(scenario_id))

    assert len(rows) == 1056
    assert tuple(int(row["row_sequence"]) for row in rows) == tuple(range(1, 1057))
    assert Counter(row["batch_id"] for row in rows) == {
        f"batch_{index:02d}": 88 for index in range(1, 13)
    }
    assert Counter(row["product"] for row in rows) == {
        "product_A": 528,
        "product_B": 528,
    }

    cell_counts = Counter(
        (row["batch_id"], row["product"], row["stream"], row["shift"]) for row in rows
    )
    assert len(cell_counts) == 96
    assert set(cell_counts.values()) == {11}
    assert {cell[1] for cell in cell_counts} == {"product_A", "product_B"}
    assert {cell[2] for cell in cell_counts} == {"stream_1", "stream_2"}
    assert {cell[3] for cell in cell_counts} == {"day", "night"}


@pytest.mark.parametrize("scenario_id", SCENARIO_ORDER, ids=lambda item: item.value)
def test_timestamps_are_unique_and_strictly_ordered_within_streams(
    scenario_id: ScenarioId,
) -> None:
    rows = _rows(generate_scenario_csv(scenario_id))
    timestamps = tuple(
        datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00")) for row in rows
    )

    assert len(set(timestamps)) == 1056
    assert all(timestamp.utcoffset() is not None for timestamp in timestamps)
    by_stream: dict[str, list[datetime]] = defaultdict(list)
    by_product_stream: dict[tuple[str, str], list[datetime]] = defaultdict(list)
    for row, timestamp in zip(rows, timestamps, strict=True):
        by_stream[row["stream"]].append(timestamp)
        by_product_stream[(row["product"], row["stream"])].append(timestamp)
    assert set(by_stream) == {"stream_1", "stream_2"}
    assert len(by_product_stream) == 4
    for ordered in (*by_stream.values(), *by_product_stream.values()):
        assert all(left < right for left, right in pairwise(ordered))


@pytest.mark.parametrize("scenario_id", SCENARIO_ORDER, ids=lambda item: item.value)
def test_quantities_are_finite_and_serialized_at_measurement_resolution(
    scenario_id: ScenarioId,
) -> None:
    rows = _rows(generate_scenario_csv(scenario_id))

    assert all(TWO_DECIMAL_QUANTITY.fullmatch(row["quantity"]) for row in rows)
    assert all(math.isfinite(float(row["quantity"])) for row in rows)


@pytest.mark.parametrize("scenario_id", SCENARIO_ORDER, ids=lambda item: item.value)
def test_generation_is_byte_reproducible_and_seed_sensitive(scenario_id: ScenarioId) -> None:
    definition = get_scenario_definition(scenario_id)
    first = generate_scenario(scenario_id)
    second = generate_scenario(scenario_id)
    changed = generate_scenario(scenario_id, seed_override=definition.seed + 1)

    assert first.definition is definition
    assert second.csv_bytes == first.csv_bytes
    assert second.dataset_sha256 == first.dataset_sha256
    assert first.dataset_sha256 == hashlib.sha256(first.csv_bytes).hexdigest()
    assert changed.definition is definition
    assert changed.csv_bytes != first.csv_bytes
    assert changed.dataset_sha256 != first.dataset_sha256
    assert definition.seed == get_scenario_definition(scenario_id).seed


@pytest.mark.parametrize(
    "definition",
    scenario_definitions(),
    ids=lambda definition: definition.scenario_id.value,
)
def test_committed_csv_matches_generator_when_asset_is_present(
    definition: ScenarioDefinition,
) -> None:
    asset = REPOSITORY_ROOT / definition.csv_asset
    if not asset.is_file():
        pytest.skip("committed Macro-03 CSV asset has not been built yet")
    assert asset.read_bytes() == generate_scenario_csv(definition.scenario_id)


def test_catalog_is_versioned_public_safe_and_self_verified() -> None:
    catalog = build_scenario_catalog()
    validate_catalog_identity(catalog)
    encoded = json_asset_bytes(catalog)
    parsed = parse_json_object(encoded)
    text = encoded.decode("utf-8")
    folded = text.casefold()

    assert encoded.endswith(b"\n") and b"\r" not in encoded
    assert parsed == catalog.to_canonical_dict()
    assert catalog.catalog_id == "riec-guard-public-scenarios.v1"
    assert catalog.catalog_version == "1.0.0"
    assert catalog.classification is PublicClassification.PUBLIC_SYNTHETIC
    assert catalog.fixed_order == SCENARIO_ORDER
    assert all(
        definition.classification is PublicClassification.PUBLIC_SYNTHETIC
        for definition in catalog.scenarios
    )
    assert "synthetic" in catalog.purpose.casefold()
    assert any(
        "not evidence of achieved savings" in item.casefold() for item in catalog.limitations
    )
    assert any("not a compliance determination" in item.casefold() for item in catalog.limitations)
    for prohibited in (
        "/users/",
        "/home/",
        "private_local_reference",
        "original_project_archives",
        "original_phase_packages",
        "frozen_reference_specs",
        "official_rules_reference",
        "submission_and_evidence_pack",
        "publisher_material",
    ):
        assert prohibited not in folded


def test_models_are_strict_immutable_and_reject_unknown_scenarios() -> None:
    design = shared_design()
    with pytest.raises(ValidationError):
        setattr(design, "row_count", 1055)
    with pytest.raises(FrozenInstanceError):
        setattr(generate_scenario(ScenarioId.STABLE_SYMMETRIC), "csv_bytes", b"")

    wrong_design = design.to_canonical_dict()
    wrong_design["row_count"] = 1055
    with pytest.raises(ValidationError):
        SharedScenarioDesign.model_validate(wrong_design)

    wrong_policy = shared_policy().to_canonical_dict()
    wrong_policy["alpha"] = "0.01"
    with pytest.raises(ValidationError):
        SharedPolicyProfile.model_validate(wrong_policy)

    extra_policy = shared_policy().to_canonical_dict()
    extra_policy["unexpected"] = True
    with pytest.raises(ValidationError):
        SharedPolicyProfile.model_validate(extra_policy)

    with pytest.raises(ValueError, match="frozen public scenario"):
        get_scenario_definition("unregistered_world")
    with pytest.raises(ValueError, match="seed_override"):
        generate_scenario_csv(ScenarioId.STABLE_SYMMETRIC, seed_override=-1)
