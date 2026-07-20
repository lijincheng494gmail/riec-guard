from __future__ import annotations

import builtins
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

from riec_guard.benchmarks.catalog import (
    build_scenario_catalog,
    canonical_sha256,
    hash_without_field,
    json_asset_bytes,
    parse_json_object,
    seal_benchmark_summary,
    validate_benchmark_identity,
    validate_record_identity,
)
from riec_guard.benchmarks.models import (
    SCENARIO_ORDER,
    DemoBenchmarkSummary,
    DemoG1State,
    ScenarioCatalog,
    ScenarioId,
)
from riec_guard.benchmarks.scenarios import generate_scenario, shared_policy
from riec_guard.contract.models import ActionState, ProtocolStatus

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = REPOSITORY_ROOT / "demo_assets/scenario_catalog.v1.json"
SUMMARY_PATH = REPOSITORY_ROOT / "demo_assets/benchmark_summary.v1.json"
BUILD_SCRIPT = REPOSITORY_ROOT / "scripts/build_demo_assets.py"

CSV_ASSETS = {
    ScenarioId.STABLE_SYMMETRIC: (REPOSITORY_ROOT / "data/public_synthetic/stable_symmetric.csv"),
    ScenarioId.HEAVY_TAIL_PARTICULATE: (
        REPOSITORY_ROOT / "data/public_synthetic/heavy_tail_particulate.csv"
    ),
    ScenarioId.BATCH_DRIFT_CHANGE_POINT: (
        REPOSITORY_ROOT / "data/public_synthetic/batch_drift_change_point.csv"
    ),
}
CSV_SHA256 = {
    ScenarioId.STABLE_SYMMETRIC: (
        "61406ba1733671cbe91350925e4e23a011bbd6b49c90d9d59ab16a74c23c8b5f"
    ),
    ScenarioId.HEAVY_TAIL_PARTICULATE: (
        "9e92d093d625de0df94c201daed84752a73791ce07eda92a16e39b9a7e22562f"
    ),
    ScenarioId.BATCH_DRIFT_CHANGE_POINT: (
        "fe3a280f6bd084e59b533083d97826d719eec58b8c01840102a6367a455abf24"
    ),
}
EXPECTED_OUTCOMES = {
    ScenarioId.STABLE_SYMMETRIC: (
        DemoG1State.PASS,
        False,
        ActionState.PILOT_RANGE_SUPPORTED,
        True,
    ),
    ScenarioId.HEAVY_TAIL_PARTICULATE: (
        DemoG1State.PASS,
        True,
        ActionState.PILOT_ONLY_CONSERVATIVE,
        True,
    ),
    ScenarioId.BATCH_DRIFT_CHANGE_POINT: (
        DemoG1State.MATERIAL_WARNING,
        True,
        ActionState.DIAGNOSE_PROCESS_FIRST,
        False,
    ),
}
SHA256_PATTERN = re.compile(r"[a-f0-9]{64}\Z")
EVIDENCE_ID_PATTERN = re.compile(r"EV-(RIEC|PROTOCOL|ACTION)-[A-F0-9]{12}\Z")
CONTRACT_ID_PATTERN = re.compile(r"AC-[A-F0-9]{12}\Z")
SENSITIVE_KEYS = frozenset(
    {
        "raw_rows",
        "raw_row",
        "row_data",
        "residuals",
        "residual_array",
        "row_predictions",
        "predictions",
        "source_run_id",
        "source_id",
        "local_path",
        "absolute_path",
        "private_root",
        "api_key",
        "authorization",
        "password",
        "secret",
        "access_token",
        "operator_name",
        "customer_name",
        "email",
        "phone",
    }
)
UNSAFE_TEXT_PATTERNS = (
    re.compile(r"(?i)\b(?:private|publisher|reviewer|manuscript)\b"),
    re.compile(r"(?i)historical[_ -]?archive"),
    re.compile(r"https?://"),
    re.compile(r"(?<![A-Za-z0-9])/(?:Users|home|private|tmp|var/tmp|var/folders)/"),
    re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:\\"),
    re.compile(r"\\\\[A-Za-z0-9._$-]+\\[A-Za-z0-9._$-]+"),
    re.compile(r"RUN-[a-f0-9]{32}"),
    re.compile(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    re.compile(r"(?i)\bBearer[ \t]+[A-Za-z0-9._~-]{16,}"),
)


def _typed_assets() -> tuple[ScenarioCatalog, DemoBenchmarkSummary]:
    catalog = ScenarioCatalog.model_validate(parse_json_object(CATALOG_PATH.read_bytes()))
    summary = DemoBenchmarkSummary.model_validate(parse_json_object(SUMMARY_PATH.read_bytes()))
    return catalog, summary


def _walk(value: object) -> tuple[tuple[str | None, object], ...]:
    found: list[tuple[str | None, object]] = []

    def visit(item: object, key: str | None = None) -> None:
        found.append((key, item))
        if isinstance(item, dict):
            for child_key, child in item.items():
                visit(child, str(child_key))
        elif isinstance(item, (list, tuple)):
            for child in item:
                visit(child)

    visit(value)
    return tuple(found)


@pytest.mark.parametrize("scenario_id", SCENARIO_ORDER)
def test_committed_scenario_csv_has_frozen_bytes_and_sha256(scenario_id: ScenarioId) -> None:
    committed = CSV_ASSETS[scenario_id].read_bytes()
    generated = generate_scenario(scenario_id)

    assert committed == generated.csv_bytes
    assert generated.dataset_sha256 == CSV_SHA256[scenario_id]
    assert hashlib.sha256(committed).hexdigest() == CSV_SHA256[scenario_id]


def test_catalog_and_recorded_summary_are_typed_canonical_and_internally_hashed() -> None:
    catalog, summary = _typed_assets()
    expected_catalog = build_scenario_catalog()

    assert catalog == expected_catalog
    assert ScenarioCatalog.model_validate(catalog.to_canonical_dict()) == catalog
    assert DemoBenchmarkSummary.model_validate(summary.to_canonical_dict()) == summary
    assert CATALOG_PATH.read_bytes() == json_asset_bytes(catalog)
    assert SUMMARY_PATH.read_bytes() == json_asset_bytes(summary)

    assert catalog.content_sha256 == hash_without_field(
        catalog.to_canonical_dict(), "content_sha256"
    )
    validate_benchmark_identity(summary, catalog=catalog)
    assert summary.catalog_sha256 == catalog.content_sha256
    assert summary.scenario_records_sha256 == canonical_sha256(
        [record.to_canonical_dict() for record in summary.scenarios]
    )
    assert summary.content_sha256 == hash_without_field(
        summary.to_canonical_dict(), "content_sha256"
    )
    for record in summary.scenarios:
        validate_record_identity(record)
        assert record.record_sha256 == hash_without_field(
            record.to_canonical_dict(), "record_sha256"
        )
    assert summary == seal_benchmark_summary(
        tuple(summary.scenarios), catalog_sha256=catalog.content_sha256
    )


def test_recorded_policy_counts_and_qualitative_outcomes_are_frozen() -> None:
    catalog, summary = _typed_assets()
    expected_policy = {
        "alpha": 0.01,
        "bootstrap_replicates": 200,
        "bootstrap_seed": 20260718,
        "lower_limit": 249.5,
        "maximum_screening_shift": 0.5,
        "measurement_resolution": 0.01,
        "min_expected_tail_count": 5,
        "minimum_actionable_shift": 0.05,
        "nominal_quantity": 250.0,
        "profile_id": "public-demo-policy.v1",
        "protocol_spread_tolerance": 0.5,
        "unit": "mL",
    }
    assert catalog.shared_policy == summary.shared_policy == shared_policy()
    assert summary.shared_policy.to_canonical_dict() == expected_policy
    assert summary.bootstrap_replicates == 200
    assert summary.bootstrap_seed == 20260718
    assert tuple(record.scenario_id for record in summary.scenarios) == SCENARIO_ORDER

    for record in summary.scenarios:
        expected_g1, expected_conflict, expected_action, expects_pilot = EXPECTED_OUTCOMES[
            record.scenario_id
        ]
        assert record.dataset_sha256 == CSV_SHA256[record.scenario_id]
        assert record.row_count == 1056
        assert record.deployment_group_count == 12
        assert record.product_count == 2
        assert record.rows_per_product == 528
        assert record.expected_tail_count_per_product == 5.28
        assert record.expected_tail_count_per_product == record.rows_per_product * 0.01
        assert record.policy_profile_id == summary.shared_policy.profile_id
        assert record.g1_state is expected_g1
        assert record.g2.status is ProtocolStatus.OK
        assert record.g2.action_supported is True
        assert record.g2.minimum_product_rows == 528
        assert record.g2.minimum_product_groups == 12
        assert record.g2.alpha == 0.01
        assert record.g2.expected_tail_count == 5.28
        assert record.g2.min_expected_tail_count == 5.0
        assert record.u1.requested_replicates == 200
        assert record.u1.successful_replicates + record.u1.failed_replicates == 200
        assert record.u1.seed == 20260718
        assert record.protocol_conflict is expected_conflict
        assert record.action_state is expected_action
        if expects_pilot:
            assert record.pilot_min is not None and record.pilot_min > 0.0
            assert record.pilot_max is not None and record.pilot_max >= record.pilot_min
        else:
            assert record.pilot_min is None
            assert record.pilot_max is None

    stable, heavy, drift = summary.scenarios
    assert stable.decisive_reason == "SUPPORTED_PILOT_REFERENCE"
    assert heavy.h2.value is not None
    assert heavy.h1.value is not None or heavy.h3.value is not None
    conservative_headroom = min(
        value for value in (heavy.h1.value, heavy.h3.value) if value is not None
    )
    assert heavy.h2.value - conservative_headroom >= 0.1
    assert heavy.protocol_spread is not None and heavy.protocol_spread > 0.0
    assert drift.decisive_reason == "ORDERED_STABILITY_MATERIAL_WARNING"


def test_recorded_evidence_and_normalized_canonical_hashes_are_structurally_bound() -> None:
    _catalog, summary = _typed_assets()

    for record in summary.scenarios:
        assert CONTRACT_ID_PATTERN.fullmatch(record.contract_id)
        assert SHA256_PATTERN.fullmatch(record.contract_sha256)
        chain = record.evidence_chain
        assert tuple(node.component for node in chain) == ("RIEC", "PROTOCOL", "ACTION")
        riec, protocol, action = chain
        assert riec.evidence_id == record.riec_evidence_id
        assert protocol.evidence_id == record.protocol_evidence_id
        assert action.evidence_id == record.action_evidence_id
        assert riec.parent_evidence_ids == ()
        assert protocol.parent_evidence_ids == (riec.evidence_id,)
        assert set(action.parent_evidence_ids) == {riec.evidence_id, protocol.evidence_id}
        assert len({node.evidence_id for node in chain}) == 3

        for node in chain:
            assert EVIDENCE_ID_PATTERN.fullmatch(node.evidence_id)
            assert SHA256_PATTERN.fullmatch(node.content_sha256)
            assert node.evidence_id == (f"EV-{node.component}-{node.content_sha256[:12].upper()}")
        normalized_hashes = (
            record.riec_selection_canonical_sha256_normalized_run_id,
            record.protocol_result_canonical_sha256_normalized_run_id,
            record.action_decision_canonical_sha256_normalized_run_id,
        )
        assert all(SHA256_PATTERN.fullmatch(value) for value in normalized_hashes)
        assert all(value != "0" * 64 for value in normalized_hashes)
        assert len(set(normalized_hashes)) == 3


def test_public_catalog_and_summary_contain_no_rows_paths_secrets_or_prohibited_claims() -> None:
    catalog, summary = _typed_assets()
    payload = {
        "catalog": catalog.to_canonical_dict(),
        "summary": summary.to_canonical_dict(),
    }
    walked = _walk(payload)

    assert not {key for key, _value in walked if key is not None} & SENSITIVE_KEYS
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    assert not any(pattern.search(serialized) for pattern in UNSAFE_TEXT_PATTERNS)
    assert "is evidence of achieved savings" not in serialized.casefold()
    assert "demonstrates compliance" not in serialized.casefold()
    assert "universally validated" not in serialized.casefold()
    assert "not evidence of achieved savings" in serialized
    assert "not evidence of achieved factory savings" in serialized
    assert "not a compliance determination" in serialized
    assert "synthetic" in serialized.casefold()


def test_fast_asset_check_does_not_import_or_invoke_analysis(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    original_import = builtins.__import__
    blocked_modules = {
        "riec_guard.app_service",
        "riec_guard.benchmarks.runner",
    }
    attempted: list[str] = []

    def guarded_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name in blocked_modules:
            attempted.append(name)
            raise AssertionError("fast asset check attempted to load analytical code")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    module_name = "_riec_guard_demo_asset_check_probe"
    spec = importlib.util.spec_from_file_location(module_name, BUILD_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)

    assert module.main(["--check"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "no analysis" in captured.out
    assert attempted == []
