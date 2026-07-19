from __future__ import annotations

import copy
import hashlib
import inspect
import json
import re
from pathlib import Path
from typing import Any, Callable

import pytest
from pydantic import ValidationError

import riec_guard.riec.registry as registry_module
from riec_guard.contract.models import CandidateRegistry, EvidenceProfile
from riec_guard.decision.claim_boundary import (
    FROZEN_BOUNDARY_CONCEPTS,
    FROZEN_CLAIM_CLASSES,
    FROZEN_PROHIBITED_CONCEPTS,
    MANDATORY_RETROSPECTIVE_PHRASE,
    ClaimClass,
    _parse_claim_ruleset,
    deterministic_export_blocking_rules,
    is_prohibited_without_external_evidence,
    list_valid_claim_classes,
    load_claim_ruleset,
    mandatory_boundary_concepts,
)
from riec_guard.protocols.registry import (
    FROZEN_POLICY_INPUT_IDS,
    FROZEN_PROTOCOL_CATEGORIES,
    FROZEN_PROTOCOL_IDS,
    ProtocolCategory,
    _parse_evidence_profile,
    _parse_policy_registry,
    _parse_protocol_registry,
    load_evidence_profile,
    load_policy_input_registry,
    load_protocol_registry,
)
from riec_guard.riec.registry import (
    FROZEN_BASELINE_CANDIDATE_ID,
    FROZEN_CANDIDATE_IDS,
    RegistryConfigError,
    RegistryConfigType,
    RegistryErrorCode,
    _parse_candidate_registry,
    load_candidate_registry,
    load_registry_manifest,
    load_run_registry_snapshot,
    verify_config_snapshot_hashes,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CONFIG_ROOT = REPOSITORY_ROOT / "configs"
REGISTERED_CONFIG_FILES = (
    "registry_manifest.v1.json",
    "candidates.fill.v1.json",
    "protocols.fill.v1.json",
    "evidence_profile.default.v1.json",
    "policy_inputs.fill.v1.json",
    "claim_rules.v1.json",
)


def _json_config(name: str) -> dict[str, Any]:
    value = json.loads((CONFIG_ROOT / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _candidate_data() -> dict[str, Any]:
    return _json_config("candidates.fill.v1.json")


def _protocol_data() -> dict[str, Any]:
    return _json_config("protocols.fill.v1.json")


def _evidence_data() -> dict[str, Any]:
    return _json_config("evidence_profile.default.v1.json")


def _policy_data() -> dict[str, Any]:
    return _json_config("policy_inputs.fill.v1.json")


def _claim_data() -> dict[str, Any]:
    return _json_config("claim_rules.v1.json")


def _expect_code(action: Callable[[], object], code: RegistryErrorCode) -> None:
    with pytest.raises(RegistryConfigError) as captured:
        action()
    assert captured.value.code is code
    public_text = str(captured.value)
    assert not re.search(r"(?:/[A-Za-z0-9._ -]+){2,}", public_text)
    assert "Traceback" not in public_text


def _synthetic_config_root(tmp_path: Path) -> Path:
    root = tmp_path / "configs"
    root.mkdir()
    for name in REGISTERED_CONFIG_FILES:
        (root / name).write_bytes((CONFIG_ROOT / name).read_bytes())
    return root


def _write_json(root: Path, name: str, payload: dict[str, Any]) -> None:
    (root / name).write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _use_synthetic_root(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    monkeypatch.setattr(registry_module, "_CONFIG_ROOT", root)


def _manifest_entry(payload: dict[str, Any], config_type: str) -> dict[str, Any]:
    entries = payload["entries"]
    assert isinstance(entries, list)
    entry = next(
        item
        for item in entries
        if isinstance(item, dict) and item.get("config_type") == config_type
    )
    return entry


def test_production_candidate_registry_validates_canonically() -> None:
    snapshot = load_candidate_registry()
    assert isinstance(snapshot.payload, CandidateRegistry)
    assert (
        CandidateRegistry.model_validate(snapshot.payload.to_canonical_dict()) == snapshot.payload
    )


def test_exactly_seven_candidates_load() -> None:
    assert len(load_candidate_registry().payload.candidates) == 7


def test_candidate_order_is_exactly_m0_through_m6() -> None:
    assert (
        tuple(item.candidate_id for item in load_candidate_registry().payload.candidates)
        == FROZEN_CANDIDATE_IDS
    )


def test_baseline_is_exactly_m0_intercept() -> None:
    assert (
        load_candidate_registry().payload.baseline_candidate_id
        == FROZEN_BASELINE_CANDIDATE_ID
        == "M0_intercept"
    )


def test_candidate_registry_is_frozen_before_ranking() -> None:
    snapshot = load_candidate_registry()
    assert snapshot.frozen and snapshot.payload.frozen_before_ranking


def test_all_candidates_are_enabled() -> None:
    assert all(item.enabled for item in load_candidate_registry().payload.candidates)


def test_formula_terms_match_frozen_specification() -> None:
    expected = {
        "M0_intercept": ("intercept",),
        "M1_product": ("intercept", "product"),
        "M2_product_stream": ("intercept", "product", "stream"),
        "M3_product_shift": ("intercept", "product", "shift"),
        "M4_product_stream_shift": ("intercept", "product", "stream", "shift"),
        "M5_product_time": ("intercept", "product", "time"),
        "M6_product_stream_shift_time": (
            "intercept",
            "product",
            "stream",
            "shift",
            "time",
        ),
    }
    actual = {
        item.candidate_id: tuple(term.value for term in item.formula_terms)
        for item in load_candidate_registry().payload.candidates
    }
    assert actual == expected


def test_required_semantics_match_formula_plus_quantity_and_group() -> None:
    for candidate in load_candidate_registry().payload.candidates:
        terms = tuple(term.value for term in candidate.formula_terms if term.value != "intercept")
        semantics = tuple(
            semantic.value for semantic in candidate.feasibility_requirements.required_semantics
        )
        assert semantics == ("quantity", *terms, "deployment_group")


def test_duplicate_candidate_id_is_rejected() -> None:
    value = _candidate_data()
    value["candidates"][1]["candidate_id"] = "M0_intercept"
    _expect_code(lambda: _parse_candidate_registry(value), RegistryErrorCode.REGISTRY_DUPLICATE_ID)


def test_missing_candidate_is_rejected() -> None:
    value = _candidate_data()
    value["candidates"].pop()
    _expect_code(
        lambda: _parse_candidate_registry(value),
        RegistryErrorCode.REGISTRY_FROZEN_SET_MISMATCH,
    )


def test_additional_eighth_candidate_is_rejected() -> None:
    value = _candidate_data()
    extra = copy.deepcopy(value["candidates"][-1])
    extra["candidate_id"] = "M7_dynamic_search"
    value["candidates"].append(extra)
    _expect_code(
        lambda: _parse_candidate_registry(value),
        RegistryErrorCode.REGISTRY_FROZEN_SET_MISMATCH,
    )


def test_invalid_baseline_is_rejected() -> None:
    value = _candidate_data()
    value["baseline_candidate_id"] = "M1_product"
    _expect_code(
        lambda: _parse_candidate_registry(value), RegistryErrorCode.REGISTRY_BASELINE_INVALID
    )


def test_disabled_baseline_is_rejected() -> None:
    value = _candidate_data()
    value["candidates"][0]["enabled"] = False
    _expect_code(
        lambda: _parse_candidate_registry(value), RegistryErrorCode.REGISTRY_BASELINE_INVALID
    )


def test_reordered_frozen_candidate_set_is_rejected() -> None:
    value = _candidate_data()
    value["candidates"][1], value["candidates"][2] = (
        value["candidates"][2],
        value["candidates"][1],
    )
    _expect_code(
        lambda: _parse_candidate_registry(value),
        RegistryErrorCode.REGISTRY_FROZEN_SET_MISMATCH,
    )


@pytest.mark.parametrize(
    ("object_id", "category"),
    [
        ("U1_whole_group_bootstrap", "uncertainty_procedure"),
        ("G1_ordered_stability_screen", "stability_gate"),
        ("G2_evidence_sufficiency_gate", "sufficiency_gate"),
        ("H1_empirical_strict_tail", "headroom_protocol"),
        ("H2_gaussian_residual_tail", "headroom_protocol"),
        ("H3_student_t_residual_tail", "headroom_protocol"),
        ("lower_limit", "policy_input"),
    ],
)
def test_noncandidate_entry_in_candidate_registry_is_rejected(
    object_id: str, category: str
) -> None:
    value = _candidate_data()
    value["candidates"].append({"object_id": object_id, "category": category})
    _expect_code(
        lambda: _parse_candidate_registry(value),
        RegistryErrorCode.REGISTRY_CROSS_TYPE_INSERTION,
    )


def test_protocols_load_with_exact_categories() -> None:
    entries = load_protocol_registry().payload.entries
    assert {item.object_id: item.category.value for item in entries} == dict(
        FROZEN_PROTOCOL_CATEGORIES
    )


def test_all_protocol_ids_are_unique() -> None:
    ids = tuple(item.object_id for item in load_protocol_registry().payload.entries)
    assert ids == FROZEN_PROTOCOL_IDS
    assert len(ids) == len(set(ids))


def test_all_protocol_entries_are_frozen() -> None:
    snapshot = load_protocol_registry()
    assert snapshot.frozen and snapshot.payload.frozen_before_execution
    assert all(item.frozen_before_execution for item in snapshot.payload.entries)


def test_no_protocol_may_enter_riec_ranking() -> None:
    assert all(
        item.may_enter_riec_ranking is False for item in load_protocol_registry().payload.entries
    )


def test_u1_is_conditional_on_selection_without_reranking() -> None:
    entries = {item.object_id: item for item in load_protocol_registry().payload.entries}
    u1 = entries["U1_whole_group_bootstrap"]
    assert u1.category is ProtocolCategory.UNCERTAINTY_PROCEDURE
    assert u1.conditional_on_selection
    assert not u1.reruns_candidate_selection


def test_g1_requires_confirmed_ordering() -> None:
    entries = {item.object_id: item for item in load_protocol_registry().payload.entries}
    assert entries["G1_ordered_stability_screen"].requires_confirmed_ordering


def test_g2_does_not_calculate_headroom() -> None:
    entries = {item.object_id: item for item in load_protocol_registry().payload.entries}
    assert not entries["G2_evidence_sufficiency_gate"].calculates_headroom


def test_d0_is_labelled_diagnostic_only() -> None:
    entries = {item.object_id: item for item in load_protocol_registry().payload.entries}
    d0 = entries["D0_mean_diagnostic"]
    assert d0.category is ProtocolCategory.DIAGNOSTIC
    assert "diagnostic only" in d0.label.casefold()
    assert d0.output_status_role == "diagnostic_context"


def test_candidate_id_in_protocol_registry_is_rejected() -> None:
    value = _protocol_data()
    value["entries"][0]["object_id"] = "M0_intercept"
    _expect_code(
        lambda: _parse_protocol_registry(value),
        RegistryErrorCode.REGISTRY_CROSS_TYPE_INSERTION,
    )


def test_duplicate_id_across_protocol_categories_is_rejected() -> None:
    value = _protocol_data()
    value["entries"][1]["object_id"] = value["entries"][0]["object_id"]
    _expect_code(lambda: _parse_protocol_registry(value), RegistryErrorCode.REGISTRY_DUPLICATE_ID)


@pytest.mark.parametrize(
    ("object_id", "wrong_category"),
    [
        ("H1_empirical_strict_tail", "uncertainty_procedure"),
        ("U1_whole_group_bootstrap", "headroom_protocol"),
        ("G1_ordered_stability_screen", "sufficiency_gate"),
        ("G2_evidence_sufficiency_gate", "stability_gate"),
    ],
)
def test_frozen_protocol_misclassification_is_rejected(object_id: str, wrong_category: str) -> None:
    value = _protocol_data()
    entry = next(item for item in value["entries"] if item["object_id"] == object_id)
    entry["category"] = wrong_category
    _expect_code(
        lambda: _parse_protocol_registry(value), RegistryErrorCode.REGISTRY_CATEGORY_INVALID
    )


def test_policy_inputs_are_typed_separately() -> None:
    snapshot = load_policy_input_registry()
    assert snapshot.config_type is RegistryConfigType.POLICY_REGISTRY
    assert tuple(item.input_id for item in snapshot.payload.inputs) == FROZEN_POLICY_INPUT_IDS
    assert all(item.category == "policy_input" for item in snapshot.payload.inputs)


def test_all_decision_critical_policy_definitions_require_confirmation() -> None:
    assert all(
        not item.decision_critical or item.confirmation_required
        for item in load_policy_input_registry().payload.inputs
    )


def test_policy_fields_cannot_enter_candidate_ranking() -> None:
    assert all(
        item.may_enter_riec_ranking is False for item in load_policy_input_registry().payload.inputs
    )
    value = _policy_data()
    value["inputs"][0]["may_enter_riec_ranking"] = True
    _expect_code(
        lambda: _parse_policy_registry(value),
        RegistryErrorCode.REGISTRY_CROSS_TYPE_INSERTION,
    )


def test_frozen_production_evidence_profile_loads() -> None:
    snapshot = load_evidence_profile()
    assert snapshot.frozen and snapshot.payload.frozen_before_run
    assert snapshot.payload.no_random_row_fallback


def test_exact_frozen_evidence_thresholds_are_preserved() -> None:
    profile = load_evidence_profile().payload
    assert (
        profile.min_rows,
        profile.min_groups_exploratory,
        profile.min_groups_action,
        profile.min_expected_tail_count,
        profile.min_ordered_points_per_stream,
        profile.minimum_ordered_coverage_fraction,
        profile.bootstrap_replicates,
        profile.bootstrap_seed,
        profile.bootstrap_min_success,
        profile.bootstrap_max_failed_fraction,
        profile.bootstrap_one_sided_confidence,
        profile.max_exact_logo_groups,
    ) == (80, 4, 8, 5, 20, 0.6, 200, 20260718, 100, 0.1, 0.9, 200)


def test_action_groups_cannot_be_below_exploratory_groups() -> None:
    value = _evidence_data()
    value["min_groups_action"] = 3
    _expect_code(lambda: _parse_evidence_profile(value), RegistryErrorCode.REGISTRY_CONFIG_INVALID)


def test_bootstrap_success_cannot_exceed_replicates() -> None:
    value = _evidence_data()
    value["bootstrap_min_success"] = 201
    _expect_code(lambda: _parse_evidence_profile(value), RegistryErrorCode.REGISTRY_CONFIG_INVALID)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("minimum_ordered_coverage_fraction", -0.01),
        ("minimum_ordered_coverage_fraction", 1.01),
        ("bootstrap_max_failed_fraction", -0.01),
        ("bootstrap_max_failed_fraction", 1.01),
        ("bootstrap_one_sided_confidence", 0.5),
        ("bootstrap_one_sided_confidence", 1.0),
    ],
)
def test_invalid_evidence_fractions_and_confidence_are_rejected(
    field: str, replacement: float
) -> None:
    value = _evidence_data()
    value[field] = replacement
    _expect_code(lambda: _parse_evidence_profile(value), RegistryErrorCode.REGISTRY_CONFIG_INVALID)


def test_evidence_profile_is_deeply_immutable() -> None:
    profile = load_evidence_profile().payload
    with pytest.raises(ValidationError):
        setattr(profile, "min_rows", 81)


def test_exact_five_claim_classes_load() -> None:
    assert tuple(item.value for item in list_valid_claim_classes()) == FROZEN_CLAIM_CLASSES


def test_exact_required_prohibited_concepts_are_present() -> None:
    snapshot = load_claim_ruleset()
    assert snapshot.payload.prohibited_without_separate_evidence == FROZEN_PROHIBITED_CONCEPTS
    assert all(
        is_prohibited_without_external_evidence(concept, snapshot)
        for concept in FROZEN_PROHIBITED_CONCEPTS
    )


def test_exact_mandatory_boundary_concepts_are_present() -> None:
    assert mandatory_boundary_concepts() == FROZEN_BOUNDARY_CONCEPTS


def test_mandatory_retrospective_phrase_is_preserved() -> None:
    assert load_claim_ruleset().payload.mandatory_phrase == MANDATORY_RETROSPECTIVE_PHRASE


def test_export_blocking_rules_load() -> None:
    rules = deterministic_export_blocking_rules()
    assert len(rules) == 5
    assert all(rule.blocks_export and rule.category == "claim_rule" for rule in rules)


@pytest.mark.parametrize(
    "field",
    ["claim_classes", "prohibited_without_separate_evidence"],
)
def test_duplicate_claim_class_or_concept_is_rejected(field: str) -> None:
    value = _claim_data()
    value[field].append(value[field][0])
    _expect_code(lambda: _parse_claim_ruleset(value), RegistryErrorCode.REGISTRY_DUPLICATE_ID)


def test_unknown_claim_class_is_rejected() -> None:
    value = _claim_data()
    value["claim_classes"][0] = "unknown"
    _expect_code(lambda: _parse_claim_ruleset(value), RegistryErrorCode.REGISTRY_CATEGORY_INVALID)


def test_claim_ruleset_must_be_frozen() -> None:
    value = _claim_data()
    value["frozen_before_audit"] = False
    _expect_code(lambda: _parse_claim_ruleset(value), RegistryErrorCode.REGISTRY_NOT_FROZEN)


def test_claim_and_protocol_cross_type_insertion_is_rejected() -> None:
    protocol = _protocol_data()
    protocol["entries"][0] = {
        "object_id": "claim_rule_object",
        "category": "claim_rule",
        "may_enter_riec_ranking": False,
    }
    _expect_code(
        lambda: _parse_protocol_registry(protocol),
        RegistryErrorCode.REGISTRY_CROSS_TYPE_INSERTION,
    )
    claims = _claim_data()
    claims["export_enforcement_rules"][0] = {
        "object_id": "H1_empirical_strict_tail",
        "category": "headroom_protocol",
    }
    _expect_code(
        lambda: _parse_claim_ruleset(claims),
        RegistryErrorCode.REGISTRY_CROSS_TYPE_INSERTION,
    )


def test_manifest_contains_every_required_config_type_once() -> None:
    manifest = load_registry_manifest()
    assert tuple(entry.config_type for entry in manifest.entries) == (
        RegistryConfigType.CANDIDATE_REGISTRY,
        RegistryConfigType.PROTOCOL_REGISTRY,
        RegistryConfigType.EVIDENCE_PROFILE,
        RegistryConfigType.POLICY_REGISTRY,
        RegistryConfigType.CLAIM_RULESET,
    )


def test_repeated_manifest_logical_id_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _synthetic_config_root(tmp_path)
    manifest = _json_config("registry_manifest.v1.json")
    manifest["entries"][1]["logical_id"] = manifest["entries"][0]["logical_id"]
    _write_json(root, "registry_manifest.v1.json", manifest)
    _use_synthetic_root(monkeypatch, root)
    _expect_code(load_registry_manifest, RegistryErrorCode.REGISTRY_DUPLICATE_ID)


def test_repeated_manifest_path_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _synthetic_config_root(tmp_path)
    manifest = _json_config("registry_manifest.v1.json")
    manifest["entries"][1]["repository_relative_path"] = manifest["entries"][0][
        "repository_relative_path"
    ]
    _write_json(root, "registry_manifest.v1.json", manifest)
    _use_synthetic_root(monkeypatch, root)
    _expect_code(load_registry_manifest, RegistryErrorCode.REGISTRY_DUPLICATE_PATH)


def test_repeated_manifest_type_version_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _synthetic_config_root(tmp_path)
    manifest = _json_config("registry_manifest.v1.json")
    manifest["entries"][1]["config_type"] = "candidate_registry"
    _write_json(root, "registry_manifest.v1.json", manifest)
    _use_synthetic_root(monkeypatch, root)
    _expect_code(load_registry_manifest, RegistryErrorCode.REGISTRY_DUPLICATE_TYPE_VERSION)


def test_unsupported_manifest_version_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _synthetic_config_root(tmp_path)
    manifest = _json_config("registry_manifest.v1.json")
    manifest["manifest_version"] = "2.0.0"
    _write_json(root, "registry_manifest.v1.json", manifest)
    _use_synthetic_root(monkeypatch, root)
    _expect_code(load_registry_manifest, RegistryErrorCode.REGISTRY_VERSION_UNSUPPORTED)


def test_missing_config_file_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _synthetic_config_root(tmp_path)
    manifest = _json_config("registry_manifest.v1.json")
    _manifest_entry(manifest, "candidate_registry")["repository_relative_path"] = "missing.json"
    _write_json(root, "registry_manifest.v1.json", manifest)
    _use_synthetic_root(monkeypatch, root)
    _expect_code(load_candidate_registry, RegistryErrorCode.REGISTRY_CONFIG_NOT_FOUND)


def test_internal_id_mismatch_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _synthetic_config_root(tmp_path)
    candidate = _candidate_data()
    candidate["registry_id"] = "different-candidate-registry.v1"
    _write_json(root, "candidates.fill.v1.json", candidate)
    _use_synthetic_root(monkeypatch, root)
    _expect_code(load_candidate_registry, RegistryErrorCode.REGISTRY_INTERNAL_ID_MISMATCH)


def test_internal_version_mismatch_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _synthetic_config_root(tmp_path)
    candidate = _candidate_data()
    candidate["registry_version"] = "1.0.1"
    _write_json(root, "candidates.fill.v1.json", candidate)
    _use_synthetic_root(monkeypatch, root)
    _expect_code(load_candidate_registry, RegistryErrorCode.REGISTRY_INTERNAL_VERSION_MISMATCH)


@pytest.mark.parametrize(
    "unsafe_path",
    ["/" + "tmp/registry.json", "../registry.json"],
)
def test_absolute_and_posix_traversal_paths_are_rejected(
    unsafe_path: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _synthetic_config_root(tmp_path)
    manifest = _json_config("registry_manifest.v1.json")
    _manifest_entry(manifest, "candidate_registry")["repository_relative_path"] = unsafe_path
    _write_json(root, "registry_manifest.v1.json", manifest)
    _use_synthetic_root(monkeypatch, root)
    _expect_code(load_registry_manifest, RegistryErrorCode.REGISTRY_PATH_UNSAFE)


@pytest.mark.parametrize(
    "unsafe_path",
    [".." + "\\registry.json", "C" + ":\\registry.json"],
)
def test_windows_traversal_and_drive_paths_are_rejected(
    unsafe_path: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _synthetic_config_root(tmp_path)
    manifest = _json_config("registry_manifest.v1.json")
    _manifest_entry(manifest, "candidate_registry")["repository_relative_path"] = unsafe_path
    _write_json(root, "registry_manifest.v1.json", manifest)
    _use_synthetic_root(monkeypatch, root)
    _expect_code(load_registry_manifest, RegistryErrorCode.REGISTRY_PATH_UNSAFE)


def test_unc_path_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _synthetic_config_root(tmp_path)
    manifest = _json_config("registry_manifest.v1.json")
    _manifest_entry(manifest, "candidate_registry")["repository_relative_path"] = (
        "\\\\server\\share\\registry.json"
    )
    _write_json(root, "registry_manifest.v1.json", manifest)
    _use_synthetic_root(monkeypatch, root)
    _expect_code(load_registry_manifest, RegistryErrorCode.REGISTRY_PATH_UNSAFE)


def test_symlink_escape_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _synthetic_config_root(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_bytes((CONFIG_ROOT / "candidates.fill.v1.json").read_bytes())
    (root / "escape.json").symlink_to(outside)
    manifest = _json_config("registry_manifest.v1.json")
    _manifest_entry(manifest, "candidate_registry")["repository_relative_path"] = "escape.json"
    _write_json(root, "registry_manifest.v1.json", manifest)
    _use_synthetic_root(monkeypatch, root)
    _expect_code(load_candidate_registry, RegistryErrorCode.REGISTRY_SYMLINK_ESCAPE)


def test_loader_does_not_discover_unregistered_extra_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _synthetic_config_root(tmp_path)
    (root / "unregistered-extra.json").write_text("not json", encoding="utf-8")
    _use_synthetic_root(monkeypatch, root)
    assert len(load_run_registry_snapshot().provenance_records()) == 5


def test_unfrozen_registry_cannot_create_run_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _synthetic_config_root(tmp_path)
    candidate = _candidate_data()
    candidate["frozen_before_ranking"] = False
    _write_json(root, "candidates.fill.v1.json", candidate)
    _use_synthetic_root(monkeypatch, root)
    _expect_code(load_run_registry_snapshot, RegistryErrorCode.REGISTRY_NOT_FROZEN)


def test_unfrozen_protocol_entry_is_rejected() -> None:
    protocol = _protocol_data()
    protocol["entries"][0]["frozen_before_execution"] = False
    _expect_code(lambda: _parse_protocol_registry(protocol), RegistryErrorCode.REGISTRY_NOT_FROZEN)


def test_unknown_manifest_category_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _synthetic_config_root(tmp_path)
    manifest = _json_config("registry_manifest.v1.json")
    manifest["entries"][0]["config_type"] = "unknown_category"
    _write_json(root, "registry_manifest.v1.json", manifest)
    _use_synthetic_root(monkeypatch, root)
    _expect_code(load_registry_manifest, RegistryErrorCode.REGISTRY_CATEGORY_INVALID)


def test_public_registry_errors_contain_no_absolute_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _synthetic_config_root(tmp_path)
    manifest = _json_config("registry_manifest.v1.json")
    sensitive_path = "/" + "tmp/sensitive-registry.json"
    _manifest_entry(manifest, "candidate_registry")["repository_relative_path"] = sensitive_path
    _write_json(root, "registry_manifest.v1.json", manifest)
    _use_synthetic_root(monkeypatch, root)
    with pytest.raises(RegistryConfigError) as captured:
        load_registry_manifest()
    public = f"{captured.value.code.value}:{captured.value}:{captured.value.logical_id}"
    assert str(tmp_path) not in public
    assert sensitive_path not in public
    assert "Traceback" not in public


def test_exact_file_hash_matches_source_bytes() -> None:
    snapshot = load_candidate_registry()
    expected = hashlib.sha256((CONFIG_ROOT / snapshot.repository_relative_source).read_bytes())
    assert snapshot.file_sha256 == expected.hexdigest()


def test_canonical_hash_matches_sorted_compact_json() -> None:
    snapshot = load_candidate_registry()
    encoded = json.dumps(
        snapshot.payload.to_canonical_dict(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    assert snapshot.canonical_json_sha256 == hashlib.sha256(encoded).hexdigest()


def test_repeated_unchanged_loads_are_identical() -> None:
    assert load_run_registry_snapshot() == load_run_registry_snapshot()


def test_whitespace_only_change_preserves_canonical_hash_but_changes_file_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    production = load_candidate_registry()
    root = _synthetic_config_root(tmp_path)
    candidate_path = root / "candidates.fill.v1.json"
    candidate_path.write_text(
        candidate_path.read_text(encoding="utf-8") + "\n  \n", encoding="utf-8"
    )
    _use_synthetic_root(monkeypatch, root)
    changed = load_candidate_registry()
    assert changed.file_sha256 != production.file_sha256
    assert changed.canonical_json_sha256 == production.canonical_json_sha256


def test_decision_critical_change_changes_canonical_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    production = load_evidence_profile()
    root = _synthetic_config_root(tmp_path)
    evidence = _evidence_data()
    evidence["min_rows"] = 81
    _write_json(root, "evidence_profile.default.v1.json", evidence)
    _use_synthetic_root(monkeypatch, root)
    changed = load_evidence_profile()
    assert changed.canonical_json_sha256 != production.canonical_json_sha256


def test_snapshot_payload_is_deeply_immutable() -> None:
    snapshot = load_candidate_registry()
    assert isinstance(snapshot.payload.candidates, tuple)
    assert isinstance(snapshot.payload.candidates[0].formula_terms, tuple)
    with pytest.raises(ValidationError):
        setattr(snapshot.payload.candidates[0], "enabled", False)


def test_caller_mutation_cannot_affect_later_load() -> None:
    first = load_candidate_registry()
    record = first.provenance_record()
    record["logical_id"] = "caller-mutated"
    second = load_candidate_registry()
    assert second.logical_id == "fill-structural-candidates.v1"
    assert second == first


def test_composite_snapshot_is_deterministic() -> None:
    first = load_run_registry_snapshot()
    second = load_run_registry_snapshot()
    assert first == second
    assert re.fullmatch(r"[a-f0-9]{64}", first.combined_canonical_sha256)


def test_composite_hash_changes_when_included_config_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    production = load_run_registry_snapshot()
    root = _synthetic_config_root(tmp_path)
    evidence = _evidence_data()
    evidence["min_rows"] = 81
    _write_json(root, "evidence_profile.default.v1.json", evidence)
    _use_synthetic_root(monkeypatch, root)
    changed = load_run_registry_snapshot()
    assert changed.combined_canonical_sha256 != production.combined_canonical_sha256


def test_composite_snapshot_contains_ids_versions_and_hashes() -> None:
    records = load_run_registry_snapshot().provenance_records()
    assert len(records) == 5
    for record in records:
        assert re.fullmatch(r"[a-f0-9]{64}", str(record["file_sha256"]))
        assert re.fullmatch(r"[a-f0-9]{64}", str(record["canonical_json_sha256"]))
        assert record["logical_id"] and record["version"] == "1.0.0"


def test_composite_snapshot_contains_no_absolute_path_or_timestamp() -> None:
    snapshot = load_run_registry_snapshot()
    serialized = json.dumps(
        {
            "configs": snapshot.provenance_records(),
            "combined_canonical_sha256": snapshot.combined_canonical_sha256,
        },
        sort_keys=True,
    )
    assert "timestamp" not in serialized
    assert "created_at" not in serialized
    assert not re.search(r"(?:/[A-Za-z0-9._ -]+){2,}", serialized)
    assert not re.search(r"[A-Za-z]:\\", serialized)


def test_hash_verification_uses_stable_hash_mismatch_code() -> None:
    snapshot = load_candidate_registry()
    _expect_code(
        lambda: verify_config_snapshot_hashes(snapshot, expected_canonical_json_sha256="0" * 64),
        RegistryErrorCode.REGISTRY_HASH_MISMATCH,
    )


def test_public_loaders_accept_logical_identity_not_paths() -> None:
    for loader in (
        load_candidate_registry,
        load_protocol_registry,
        load_evidence_profile,
        load_policy_input_registry,
        load_claim_ruleset,
    ):
        parameters = inspect.signature(loader).parameters
        assert "path" not in parameters
        assert "root" not in parameters


def test_candidate_snapshot_agrees_with_canonical_example() -> None:
    example = json.loads(
        (REPOSITORY_ROOT / "schemas/examples/candidate_registry.example.json").read_text(
            encoding="utf-8"
        )
    )
    assert load_candidate_registry().payload.to_canonical_dict() == example


def test_evidence_defaults_agree_with_task010_contract_shape() -> None:
    profile = load_evidence_profile().payload.to_contract_evidence_profile()
    assert isinstance(profile, EvidenceProfile)
    assert profile.to_canonical_dict() == {
        "profile_version": "1.0.0",
        "min_rows": 80,
        "min_groups_exploratory": 4,
        "min_groups_action": 8,
        "min_expected_tail_count": 5,
        "min_ordered_points_per_stream": 20,
        "min_ordered_coverage": 0.6,
        "bootstrap_replicates": 200,
        "bootstrap_lower_confidence": 0.9,
        "bootstrap_max_failure_fraction": 0.1,
    }


def test_frozen_candidate_schema_example_and_index_hashes_are_unchanged() -> None:
    expected = {
        "schemas/SCHEMA_INDEX.json": (
            "e88012d093c2d06962930292bb9716a539cc7e2984e15438847022eabd30aacc"
        ),
        "schemas/canonical/CANDIDATE_REGISTRY_SCHEMA.json": (
            "eb2ba147531777d33ecea1a1115789e025b2a38ac7061fffc611095b143cc1cb"
        ),
        "schemas/examples/candidate_registry.example.json": (
            "52ef523ad14e3366af88251ce2831f5da69db3a7641e18af9979313985f8b2d3"
        ),
    }
    for relative, digest in expected.items():
        assert hashlib.sha256((REPOSITORY_ROOT / relative).read_bytes()).hexdigest() == digest


def test_requirements_lock_hash_is_unchanged() -> None:
    assert hashlib.sha256((REPOSITORY_ROOT / "requirements.lock").read_bytes()).hexdigest() == (
        "82116ddca67ef3da9b8bbf54942eb186cfcf6ace0b284dfdeabba9644effb76e"
    )


def test_registry_error_code_set_is_exact_and_stable() -> None:
    assert tuple(code.value for code in RegistryErrorCode) == (
        "REGISTRY_CONFIG_NOT_FOUND",
        "REGISTRY_CONFIG_INVALID",
        "REGISTRY_MANIFEST_INVALID",
        "REGISTRY_VERSION_UNSUPPORTED",
        "REGISTRY_PATH_UNSAFE",
        "REGISTRY_DUPLICATE_ID",
        "REGISTRY_DUPLICATE_PATH",
        "REGISTRY_DUPLICATE_TYPE_VERSION",
        "REGISTRY_INTERNAL_ID_MISMATCH",
        "REGISTRY_INTERNAL_VERSION_MISMATCH",
        "REGISTRY_NOT_FROZEN",
        "REGISTRY_FROZEN_SET_MISMATCH",
        "REGISTRY_BASELINE_INVALID",
        "REGISTRY_CATEGORY_INVALID",
        "REGISTRY_CROSS_TYPE_INSERTION",
        "REGISTRY_HASH_MISMATCH",
        "REGISTRY_SYMLINK_ESCAPE",
    )


def test_config_categories_include_all_required_separate_classes() -> None:
    required = {
        "predictive_candidate",
        "diagnostic",
        "headroom_protocol",
        "uncertainty_procedure",
        "stability_gate",
        "sufficiency_gate",
        "policy_input",
        "evidence_profile",
        "claim_rule",
    }
    assert required <= {item.value for item in RegistryConfigType}
    assert set(FROZEN_CLAIM_CLASSES) == {item.value for item in ClaimClass}
