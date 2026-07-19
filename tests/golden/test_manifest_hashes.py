from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from riec_guard.riec.registry import load_run_registry_snapshot
from riec_guard.settings import SeedSettings
from riec_guard.telemetry.manifest import (
    CHECKSUM_INVENTORY_PATH,
    ManifestError,
    ManifestErrorCode,
    RunManifestBuilder,
    collect_code_provenance,
    collect_environment_provenance,
    manifest_sha256,
    parse_checksum_inventory,
    registries_from_snapshot,
    render_checksum_inventory,
    verify_checksum_inventory,
    verify_manifest,
    write_checksum_inventory,
)
from riec_guard.telemetry.models import (
    ManifestArtifact,
    ManifestRegistries,
    RunManifest,
    RunStatus,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_PATH = REPOSITORY_ROOT / "schemas/examples/run_manifest.example.json"
RUN_ID = "RUN-ABCDEF123456"
STARTED_AT = "2026-07-19T00:00:00Z"
FINISHED_AT = "2026-07-19T00:01:00Z"
LOCK_HASH = "1" * 64
INPUT_HASH = "2" * 64
CONTRACT_HASH = "3" * 64
CANDIDATE_HASH = "4" * 64
FROZEN_MANIFEST_HASH = "b4d580adf97b38c32abaca9f195502ab838bb591dad11f3c23475de5b2c16700"


def _example_payload() -> dict[str, object]:
    value = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _base_builder(
    tmp_path: Path,
    *,
    run_id: str = RUN_ID,
    contract_id: str = "AC-ABCDEF123456",
    artifact_root: Path | None = None,
    registries: object | None = None,
    mode: str = "public_builtin",
    storage_root_class: str = "public_ephemeral",
    release_scan_passed: bool = False,
    store: bool = False,
) -> tuple[RunManifestBuilder, Path]:
    artifact_root = artifact_root or tmp_path / run_id / "artifacts"
    artifact_root.mkdir(parents=True, exist_ok=True)
    manifest_registries = (
        registries
        if registries is not None
        else {
            "candidate_registry": {
                "id": "fill-structural-candidates.v1",
                "version": "1.0.0",
                "sha256": CANDIDATE_HASH,
            },
            "protocol_versions": {"H1_empirical_strict_tail": "1.0.0"},
            "action_engine_version": "1.0.0",
        }
    )
    builder = RunManifestBuilder(
        run_id=run_id,
        mode=mode,
        started_at=STARTED_AT,
        code={
            "repository": "riec-guard",
            "commit_sha": "a" * 40,
            "dirty": False,
            "build_week_delta_version": "1.0.0",
        },
        environment={
            "python": "3.12.13",
            "platform": "Darwin arm64",
            "dependency_lock_sha256": LOCK_HASH,
        },
        contract={
            "contract_id": contract_id,
            "sha256": CONTRACT_HASH,
            "schema_version": "1.0.0",
            "confirmation_status": "confirmed",
        },
        registries=manifest_registries,  # type: ignore[arg-type]
        randomness={
            "global_seed": 20260718,
            "bootstrap_seed": 20260718,
            "bootstrap_replicates": 200,
        },
        configured_model="gpt-5.6-sol",
        artifact_root=artifact_root,
        storage_root_class=storage_root_class,
        release_scan_passed=release_scan_passed,
        store=store,
    )
    return builder, artifact_root


def _prepare_builder(
    tmp_path: Path,
    *,
    mode: str = "public_builtin",
    classification: str = "public_synthetic",
    storage_root_class: str = "public_ephemeral",
    public_safe: bool = True,
    release_scan_passed: bool = False,
) -> tuple[RunManifestBuilder, Path]:
    builder, artifact_root = _base_builder(
        tmp_path,
        mode=mode,
        storage_root_class=storage_root_class,
        release_scan_passed=release_scan_passed,
    )
    builder.register_input(
        artifact_id="fixture.v1",
        sha256=INPUT_HASH,
        classification=classification,
        row_count=3,
    )
    (artifact_root / "result.json").write_text("{}", encoding="utf-8")
    builder.register_artifact(
        artifact_id="result.json",
        relative_path="result.json",
        media_type="application/json",
        public_safe=public_safe,
    )
    return builder, artifact_root


def _completed_manifest(
    tmp_path: Path,
    **options: object,
) -> tuple[RunManifest, Path, RunManifestBuilder]:
    builder, artifact_root = _prepare_builder(tmp_path, **options)  # type: ignore[arg-type]
    builder.start().complete(finished_at=FINISHED_AT)
    result = builder.finalize()
    return result.manifest, artifact_root, builder


def _expect_code(error: pytest.ExceptionInfo[ManifestError], code: ManifestErrorCode) -> None:
    assert error.value.code is code


def test_frozen_run_manifest_example_validates_through_canonical_model_and_schema() -> None:
    manifest = RunManifest.model_validate(_example_payload())
    assert manifest.schema_version == "1.0.0"


def test_frozen_example_round_trips_without_json_object_information_loss() -> None:
    payload = _example_payload()
    assert RunManifest.model_validate(payload).to_canonical_dict() == payload


def test_frozen_example_canonical_manifest_sha256_is_fixed() -> None:
    assert manifest_sha256(RunManifest.model_validate(_example_payload())) == FROZEN_MANIFEST_HASH


def test_repeated_complete_manifest_hashing_is_deterministic() -> None:
    manifest = RunManifest.model_validate(_example_payload())
    assert manifest_sha256(manifest) == manifest_sha256(manifest)


def test_any_canonical_field_change_changes_manifest_sha256() -> None:
    payload = _example_payload()
    original = RunManifest.model_validate(payload)
    changed_payload = json.loads(json.dumps(payload))
    changed_payload["privacy"]["release_scan_passed"] = False
    changed = RunManifest.model_validate(changed_payload)
    assert manifest_sha256(original) != manifest_sha256(changed)


def test_manifest_hash_is_external_and_not_injected_into_canonical_object() -> None:
    manifest = RunManifest.model_validate(_example_payload())
    digest = manifest_sha256(manifest)
    assert digest not in json.dumps(manifest.to_canonical_dict())
    assert "manifest_sha256" not in manifest.to_canonical_dict()


def test_manifest_hash_rejects_sensitive_canonical_content() -> None:
    payload = _example_payload()
    payload["fallbacks"] = [
        {
            "component": "memo_draft",
            "trigger": "/" + "Users" + "/operator/private.csv",
            "fallback": "deterministic template",
            "honesty_label": "GPT unavailable",
        }
    ]
    manifest = RunManifest.model_validate(payload)
    with pytest.raises(ManifestError) as caught:
        manifest_sha256(manifest)
    _expect_code(caught, ManifestErrorCode.MANIFEST_ABSOLUTE_PATH)


def test_valid_created_running_completed_lifecycle_passes(tmp_path: Path) -> None:
    manifest, artifact_root, _ = _completed_manifest(tmp_path)
    assert manifest.status is RunStatus.COMPLETED
    assert (
        verify_manifest(manifest, artifact_root=artifact_root).artifact_verification.artifact_count
        == 1
    )


def test_valid_completed_with_warnings_lifecycle_passes(tmp_path: Path) -> None:
    builder, _ = _prepare_builder(tmp_path)
    builder.start().complete(finished_at=FINISHED_AT, with_warnings=True)
    assert builder.finalize().manifest.status is RunStatus.COMPLETED_WITH_WARNINGS


def test_valid_created_failed_lifecycle_passes(tmp_path: Path) -> None:
    builder, _ = _prepare_builder(tmp_path)
    builder.fail(finished_at=FINISHED_AT)
    assert builder.finalize().manifest.status is RunStatus.FAILED


def test_valid_running_failed_lifecycle_passes(tmp_path: Path) -> None:
    builder, _ = _prepare_builder(tmp_path)
    builder.start().fail(finished_at=FINISHED_AT)
    assert builder.finalize().manifest.status is RunStatus.FAILED


def test_terminal_to_running_transition_is_rejected(tmp_path: Path) -> None:
    builder, _ = _prepare_builder(tmp_path)
    builder.start().complete(finished_at=FINISHED_AT)
    with pytest.raises(ManifestError) as caught:
        builder.start()
    _expect_code(caught, ManifestErrorCode.MANIFEST_INVALID_TRANSITION)


def test_finished_time_before_start_time_is_rejected(tmp_path: Path) -> None:
    builder, _ = _prepare_builder(tmp_path)
    builder.start()
    with pytest.raises(ManifestError) as caught:
        builder.complete(finished_at="2026-07-18T23:59:59Z")
    _expect_code(caught, ManifestErrorCode.MANIFEST_TIMESTAMP_INVALID)


def test_nonterminal_manifest_with_finished_time_is_rejected(tmp_path: Path) -> None:
    manifest, artifact_root, _ = _completed_manifest(tmp_path)
    invalid = manifest.model_copy(update={"status": RunStatus.RUNNING})
    with pytest.raises(ManifestError) as caught:
        verify_manifest(invalid, artifact_root=artifact_root)
    _expect_code(caught, ManifestErrorCode.MANIFEST_TIMESTAMP_INVALID)


def test_terminal_manifest_without_finished_time_is_rejected(tmp_path: Path) -> None:
    manifest, artifact_root, _ = _completed_manifest(tmp_path)
    invalid = manifest.model_copy(update={"finished_at": None})
    with pytest.raises(ManifestError) as caught:
        verify_manifest(invalid, artifact_root=artifact_root)
    _expect_code(caught, ManifestErrorCode.MANIFEST_TIMESTAMP_INVALID)


def test_repeated_identical_terminal_transition_is_idempotent(tmp_path: Path) -> None:
    builder, _ = _prepare_builder(tmp_path)
    builder.start().complete(finished_at=FINISHED_AT)
    assert builder.complete(finished_at=FINISHED_AT) is builder


def test_changed_terminal_transition_is_rejected(tmp_path: Path) -> None:
    builder, _ = _prepare_builder(tmp_path)
    builder.start().complete(finished_at=FINISHED_AT)
    with pytest.raises(ManifestError) as caught:
        builder.complete(finished_at="2026-07-19T00:02:00Z")
    _expect_code(caught, ManifestErrorCode.MANIFEST_INVALID_TRANSITION)


def test_public_builtin_mode_privacy_input_combination_passes(tmp_path: Path) -> None:
    manifest, _, _ = _completed_manifest(tmp_path)
    assert manifest.mode.value == "public_builtin"
    assert manifest.privacy.storage_root_class.value == "public_ephemeral"


def test_public_upload_mode_privacy_input_combination_passes(tmp_path: Path) -> None:
    manifest, _, _ = _completed_manifest(
        tmp_path,
        mode="public_upload",
        classification="public_upload",
    )
    assert manifest.mode.value == "public_upload"


def test_valid_local_private_combination_passes(tmp_path: Path) -> None:
    manifest, _, _ = _completed_manifest(
        tmp_path,
        mode="local_private",
        classification="private_industrial",
        storage_root_class="private_local",
    )
    assert manifest.mode.value == "local_private"


def test_local_private_mode_may_use_public_synthetic_input(tmp_path: Path) -> None:
    manifest, _, _ = _completed_manifest(
        tmp_path,
        mode="local_private",
        classification="public_synthetic",
        storage_root_class="private_local",
    )
    assert manifest.inputs[0].classification.value == "public_synthetic"


def test_private_input_in_public_mode_is_rejected(tmp_path: Path) -> None:
    builder, _ = _prepare_builder(tmp_path, classification="private_industrial")
    builder.start().complete(finished_at=FINISHED_AT)
    with pytest.raises(ManifestError) as caught:
        builder.finalize()
    _expect_code(caught, ManifestErrorCode.MANIFEST_MODE_PRIVACY_MISMATCH)


def test_private_local_storage_in_public_mode_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ManifestError) as caught:
        _base_builder(tmp_path, storage_root_class="private_local")
    _expect_code(caught, ManifestErrorCode.MANIFEST_MODE_PRIVACY_MISMATCH)


def test_public_ephemeral_storage_for_private_mode_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ManifestError) as caught:
        _base_builder(tmp_path, mode="local_private")
    _expect_code(caught, ManifestErrorCode.MANIFEST_MODE_PRIVACY_MISMATCH)


def test_gpt_store_true_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ManifestError) as caught:
        _base_builder(tmp_path, store=True)
    _expect_code(caught, ManifestErrorCode.MANIFEST_GPT_INVALID)


def test_gpt_prompt_or_message_field_cannot_enter_manifest(tmp_path: Path) -> None:
    manifest, artifact_root, _ = _completed_manifest(tmp_path)
    payload = manifest.to_canonical_dict()
    payload["gpt"]["prompt"] = "confidential"  # type: ignore[index]
    with pytest.raises(ManifestError) as caught:
        verify_manifest(payload, artifact_root=artifact_root)
    _expect_code(caught, ManifestErrorCode.MANIFEST_SECRET_CONTENT)


def test_safe_gpt_call_telemetry_passes(tmp_path: Path) -> None:
    builder, _ = _prepare_builder(tmp_path)
    record = builder.register_gpt_call(
        purpose="memo_draft",
        status="success",
        request_id="resp_safe_123",
        model="gpt-5.6-sol",
        latency_ms=10,
        input_tokens=20,
        output_tokens=5,
        fallback_used=False,
        error_class=None,
    )
    assert record.status.value == "success"


def test_repeated_gpt_purpose_records_distinct_calls(tmp_path: Path) -> None:
    builder, _ = _prepare_builder(tmp_path)
    fields = {
        "purpose": "memo_draft",
        "status": "success",
        "request_id": "resp_safe_123",
        "model": "gpt-5.6-sol",
        "latency_ms": 10,
        "input_tokens": 20,
        "output_tokens": 5,
        "fallback_used": False,
        "error_class": None,
    }
    builder.register_gpt_call(**fields)  # type: ignore[arg-type]
    fields["request_id"] = "resp_safe_456"
    builder.register_gpt_call(**fields)  # type: ignore[arg-type]
    builder.start().complete(finished_at=FINISHED_AT)
    assert len(builder.finalize().manifest.gpt.calls) == 2


def test_fallback_gpt_call_requires_matching_honesty_record(tmp_path: Path) -> None:
    builder, _ = _prepare_builder(tmp_path)
    builder.register_gpt_call(
        purpose="memo_draft",
        status="fallback",
        request_id=None,
        model=None,
        latency_ms=None,
        input_tokens=None,
        output_tokens=None,
        fallback_used=True,
        error_class="ApiUnavailable",
    )
    builder.start().complete(finished_at=FINISHED_AT, with_warnings=True)
    with pytest.raises(ManifestError) as caught:
        builder.finalize()
    _expect_code(caught, ManifestErrorCode.MANIFEST_GPT_INVALID)


def test_fallback_gpt_call_with_matching_honesty_record_passes(tmp_path: Path) -> None:
    builder, _ = _prepare_builder(tmp_path)
    builder.register_gpt_call(
        purpose="memo_draft",
        status="fallback",
        request_id=None,
        model=None,
        latency_ms=None,
        input_tokens=None,
        output_tokens=None,
        fallback_used=True,
        error_class="ApiUnavailable",
    )
    builder.register_fallback(
        component="memo_draft",
        trigger="API unavailable",
        fallback="deterministic template",
        honesty_label="GPT draft unavailable",
    )
    builder.start().complete(finished_at=FINISHED_AT, with_warnings=True)
    assert builder.finalize().manifest.fallbacks[0].component == "memo_draft"


def test_not_called_does_not_falsely_claim_request_or_model(tmp_path: Path) -> None:
    builder, _ = _prepare_builder(tmp_path)
    with pytest.raises(ManifestError) as caught:
        builder.register_gpt_call(
            purpose="contract_compile",
            status="not_called",
            request_id="resp_false",
            model="gpt-5.6-sol",
            latency_ms=None,
            input_tokens=None,
            output_tokens=None,
            fallback_used=False,
            error_class=None,
        )
    _expect_code(caught, ManifestErrorCode.MANIFEST_GPT_INVALID)


def test_failed_gpt_call_requires_safe_error_class(tmp_path: Path) -> None:
    builder, _ = _prepare_builder(tmp_path)
    with pytest.raises(ManifestError) as caught:
        builder.register_gpt_call(
            purpose="claim_audit",
            status="failed",
            request_id=None,
            model=None,
            latency_ms=1,
            input_tokens=None,
            output_tokens=None,
            fallback_used=False,
            error_class=None,
        )
    _expect_code(caught, ManifestErrorCode.MANIFEST_GPT_INVALID)


def test_secret_like_telemetry_is_rejected_without_echoing_value(tmp_path: Path) -> None:
    builder, _ = _prepare_builder(tmp_path)
    secret = "sk-" + "A" * 16
    with pytest.raises(ManifestError) as caught:
        builder.register_fallback(
            component="memo_draft",
            trigger=secret,
            fallback="deterministic template",
            honesty_label="GPT unavailable",
        )
    _expect_code(caught, ManifestErrorCode.MANIFEST_SECRET_CONTENT)
    assert secret not in str(caught.value)


@pytest.mark.parametrize(
    "secret",
    [
        "AKIA" + "A" * 16,
        "ghp_" + "a" * 20,
        "github_pat_" + "a" * 20,
    ],
)
def test_cloud_and_source_control_credentials_are_rejected(
    tmp_path: Path,
    secret: str,
) -> None:
    builder, _ = _prepare_builder(tmp_path)
    with pytest.raises(ManifestError) as caught:
        builder.register_fallback(
            component="memo_draft",
            trigger=secret,
            fallback="deterministic template",
            honesty_label="GPT unavailable",
        )
    _expect_code(caught, ManifestErrorCode.MANIFEST_SECRET_CONTENT)


@pytest.mark.parametrize(
    "unsafe_text",
    [
        "file:" + "/" * 3 + "Users/operator/private.csv",
        "file:" + "/" + "Users/operator/private.csv",
        "path:" + "/" + "Users/operator/private.csv",
        "path:C" + ":" + "/" + "Users/operator/private.csv",
        "path:" + "\\" * 2 + "server\\share\\private.csv",
        "~/private.csv",
        "~operator/private.csv",
        "../private.csv",
        "bad\x00value",
    ],
)
def test_local_paths_and_controls_are_rejected_from_fallbacks(
    tmp_path: Path,
    unsafe_text: str,
) -> None:
    builder, _ = _prepare_builder(tmp_path)
    with pytest.raises(ManifestError) as caught:
        builder.register_fallback(
            component="memo_draft",
            trigger=unsafe_text,
            fallback="deterministic template",
            honesty_label="GPT unavailable",
        )
    assert caught.value.code in {
        ManifestErrorCode.MANIFEST_ABSOLUTE_PATH,
        ManifestErrorCode.MANIFEST_SECRET_CONTENT,
    }


def test_automatic_code_environment_collector_stores_no_path_or_username() -> None:
    code = collect_code_provenance(
        REPOSITORY_ROOT,
        build_week_delta_version="1.0.0",
    )
    environment = collect_environment_provenance(REPOSITORY_ROOT)
    serialized = json.dumps(
        {"code": code.to_canonical_dict(), "environment": environment.to_canonical_dict()}
    )
    assert str(REPOSITORY_ROOT) not in serialized
    assert code.repository == "riec-guard"
    assert "/" not in environment.platform


def test_dependency_lock_sha_matches_exact_bytes() -> None:
    environment = collect_environment_provenance(REPOSITORY_ROOT)
    expected = hashlib.sha256((REPOSITORY_ROOT / "requirements.lock").read_bytes()).hexdigest()
    assert environment.dependency_lock_sha256 == expected
    assert expected == "82116ddca67ef3da9b8bbf54942eb186cfcf6ace0b284dfdeabba9644effb76e"


@pytest.mark.parametrize("lock_name", ["nested/requirements.lock", "bad\x00name.lock"])
def test_dependency_lock_collector_rejects_unsafe_filename(lock_name: str) -> None:
    with pytest.raises(ManifestError) as caught:
        collect_environment_provenance(REPOSITORY_ROOT, dependency_lock_name=lock_name)
    _expect_code(caught, ManifestErrorCode.MANIFEST_ABSOLUTE_PATH)


def test_missing_lock_error_suppresses_path_bearing_cause() -> None:
    with pytest.raises(ManifestError) as caught:
        collect_environment_provenance(
            REPOSITORY_ROOT,
            dependency_lock_name="missing-task012.lock",
        )
    _expect_code(caught, ManifestErrorCode.MANIFEST_SCHEMA_INVALID)
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__ is True
    assert str(REPOSITORY_ROOT) not in str(caught.value)


def test_task011_candidate_snapshot_populates_identity_correctly() -> None:
    snapshot = load_run_registry_snapshot()
    registries = registries_from_snapshot(snapshot, action_engine_version="1.0.0")
    assert registries.candidate_registry.id == snapshot.candidate_registry.logical_id
    assert registries.candidate_registry.version == snapshot.candidate_registry.version
    assert registries.candidate_registry.sha256 == snapshot.candidate_registry.canonical_json_sha256


def test_task011_protocol_snapshot_populates_versions_correctly() -> None:
    snapshot = load_run_registry_snapshot()
    registries = registries_from_snapshot(snapshot, action_engine_version="1.0.0")
    expected = {
        entry.object_id: entry.version for entry in snapshot.protocol_registry.payload.entries
    }
    assert dict(registries.protocol_versions) == expected


def test_unsupported_extra_registry_fields_are_not_invented() -> None:
    registries = registries_from_snapshot(
        load_run_registry_snapshot(), action_engine_version="1.0.0"
    )
    assert set(registries.to_canonical_dict()) == {
        "candidate_registry",
        "protocol_versions",
        "action_engine_version",
    }


def test_protocol_version_key_with_secret_suffix_is_rejected(tmp_path: Path) -> None:
    artifact_root = tmp_path / RUN_ID / "artifacts"
    artifact_root.mkdir(parents=True)
    with pytest.raises(ManifestError) as caught:
        RunManifestBuilder(
            run_id=RUN_ID,
            mode="public_builtin",
            started_at=STARTED_AT,
            code={
                "repository": "riec-guard",
                "commit_sha": "a" * 40,
                "dirty": False,
                "build_week_delta_version": "1.0.0",
            },
            environment={
                "python": "3.12.13",
                "platform": "Darwin arm64",
                "dependency_lock_sha256": LOCK_HASH,
            },
            contract={
                "contract_id": "AC-ABCDEF123456",
                "sha256": CONTRACT_HASH,
                "schema_version": "1.0.0",
                "confirmation_status": "confirmed",
            },
            registries={
                "candidate_registry": {
                    "id": "fill-structural-candidates.v1",
                    "version": "1.0.0",
                    "sha256": CANDIDATE_HASH,
                },
                "protocol_versions": {"service_access_token": "1.0.0"},
                "action_engine_version": "1.0.0",
            },
            randomness={
                "global_seed": 1,
                "bootstrap_seed": 1,
                "bootstrap_replicates": 1,
            },
            configured_model="gpt-5.6-sol",
            artifact_root=artifact_root,
            storage_root_class="public_ephemeral",
        )
    _expect_code(caught, ManifestErrorCode.MANIFEST_SECRET_CONTENT)


def test_protocol_version_key_with_control_character_is_rejected(tmp_path: Path) -> None:
    registries = {
        "candidate_registry": {
            "id": "fill-structural-candidates.v1",
            "version": "1.0.0",
            "sha256": CANDIDATE_HASH,
        },
        "protocol_versions": {"bad\x00key": "1.0.0"},
        "action_engine_version": "1.0.0",
    }
    with pytest.raises(ManifestError) as caught:
        _base_builder(tmp_path, registries=registries)
    _expect_code(caught, ManifestErrorCode.MANIFEST_SECRET_CONTENT)


def test_artifact_registration_stores_relative_posix_path(tmp_path: Path) -> None:
    builder, artifact_root = _base_builder(tmp_path)
    nested = artifact_root / "reports"
    nested.mkdir()
    (nested / "result.json").write_text("{}", encoding="utf-8")
    artifact = builder.register_artifact(
        artifact_id="result.json",
        relative_path="reports/result.json",
        media_type="application/json",
        public_safe=True,
    )
    assert artifact.path == "reports/result.json"
    assert not artifact.path.startswith("/")


def test_current_runtime_run_root_binds_by_canonical_prefix(tmp_path: Path) -> None:
    settings = SeedSettings(ephemeral_root=tmp_path / "runtime")
    roots = settings.create_run_roots()
    canonical_run_id = f"RUN-{roots.run_id[4:16].upper()}"
    builder, artifact_root = _base_builder(
        tmp_path,
        run_id=canonical_run_id,
        artifact_root=roots.artifacts,
    )
    assert artifact_root == roots.artifacts
    assert builder.run_id == canonical_run_id


def test_runtime_run_root_with_mismatched_prefix_is_rejected(tmp_path: Path) -> None:
    runtime_root = tmp_path / ("RUN-" + "f" * 32) / "artifacts"
    runtime_root.mkdir(parents=True)
    with pytest.raises(ManifestError) as caught:
        _base_builder(tmp_path, artifact_root=runtime_root)
    _expect_code(caught, ManifestErrorCode.ARTIFACT_PATH_UNSAFE)


@pytest.mark.parametrize(
    "storage_run_id",
    [
        "arbitrary-run",
        "RUN-abcdef123456ABCDEF123456abcdef12",
        "RUN-abcdef123456abcdef123456abcdef1",
    ],
)
def test_malformed_runtime_artifact_root_is_rejected(
    tmp_path: Path,
    storage_run_id: str,
) -> None:
    artifact_root = tmp_path / storage_run_id / "artifacts"
    artifact_root.mkdir(parents=True)
    with pytest.raises(ManifestError) as caught:
        _base_builder(tmp_path, artifact_root=artifact_root)
    _expect_code(caught, ManifestErrorCode.ARTIFACT_PATH_UNSAFE)


def test_canonical_run_root_remains_accepted(tmp_path: Path) -> None:
    builder, artifact_root = _base_builder(tmp_path)
    assert artifact_root.parent.name == builder.run_id


def test_all_numeric_canonical_run_and_contract_ids_remain_valid(tmp_path: Path) -> None:
    numeric_run_id = "RUN-123456789012"
    builder, artifact_root = _base_builder(
        tmp_path,
        run_id=numeric_run_id,
        contract_id="AC-123456789012",
    )
    builder.register_input(
        artifact_id="fixture.v1",
        sha256=INPUT_HASH,
        classification="public_synthetic",
        row_count=3,
    )
    (artifact_root / "result.json").write_text("{}", encoding="utf-8")
    builder.register_artifact(
        artifact_id="result.json",
        relative_path="result.json",
        media_type="application/json",
        public_safe=True,
    )
    builder.start().complete(finished_at=FINISHED_AT)
    assert builder.finalize().manifest.run_id == numeric_run_id


def test_manifest_builder_detaches_mutable_registry_alias(tmp_path: Path) -> None:
    alias = {"H1_empirical_strict_tail": "1.0.0"}
    registries = ManifestRegistries.model_validate(
        {
            "candidate_registry": {
                "id": "fill-structural-candidates.v1",
                "version": "1.0.0",
                "sha256": CANDIDATE_HASH,
            },
            "protocol_versions": alias,
            "action_engine_version": "1.0.0",
        }
    ).model_copy(update={"protocol_versions": alias})
    builder, artifact_root = _base_builder(tmp_path, registries=registries)
    alias["H2_gaussian_residual_tail"] = "1.0.0"
    builder.register_input(
        artifact_id="fixture.v1",
        sha256=INPUT_HASH,
        classification="public_synthetic",
        row_count=3,
    )
    (artifact_root / "result.json").write_text("{}", encoding="utf-8")
    builder.register_artifact(
        artifact_id="result.json",
        relative_path="result.json",
        media_type="application/json",
        public_safe=True,
    )
    builder.start().complete(finished_at=FINISHED_AT)
    versions = builder.finalize().manifest.registries.protocol_versions
    assert set(versions) == {"H1_empirical_strict_tail"}


def test_absolute_artifact_path_is_rejected(tmp_path: Path) -> None:
    builder, artifact_root = _base_builder(tmp_path)
    target = artifact_root / "result.json"
    target.write_text("{}", encoding="utf-8")
    with pytest.raises(ManifestError) as caught:
        builder.register_artifact(
            artifact_id="result.json",
            relative_path=str(target),
            media_type="application/json",
            public_safe=True,
        )
    _expect_code(caught, ManifestErrorCode.ARTIFACT_PATH_UNSAFE)


def test_posix_traversal_is_rejected(tmp_path: Path) -> None:
    builder, _ = _base_builder(tmp_path)
    traversal = "reports/" + ".." + "/result.json"
    with pytest.raises(ManifestError) as caught:
        builder.register_artifact(
            artifact_id="result.json",
            relative_path=traversal,
            media_type="application/json",
            public_safe=True,
        )
    _expect_code(caught, ManifestErrorCode.ARTIFACT_PATH_UNSAFE)


def test_windows_drive_path_is_rejected(tmp_path: Path) -> None:
    builder, _ = _base_builder(tmp_path)
    drive_path = "C" + ":" + "\\" + "data" + "\\" + "result.json"
    with pytest.raises(ManifestError) as caught:
        builder.register_artifact(
            artifact_id="result.json",
            relative_path=drive_path,
            media_type="application/json",
            public_safe=True,
        )
    _expect_code(caught, ManifestErrorCode.ARTIFACT_PATH_UNSAFE)


def test_unc_path_is_rejected(tmp_path: Path) -> None:
    builder, _ = _base_builder(tmp_path)
    unc_path = "\\" * 2 + "server" + "\\share\\result.json"
    with pytest.raises(ManifestError) as caught:
        builder.register_artifact(
            artifact_id="result.json",
            relative_path=unc_path,
            media_type="application/json",
            public_safe=True,
        )
    _expect_code(caught, ManifestErrorCode.ARTIFACT_PATH_UNSAFE)


def test_escaping_symlink_is_rejected(tmp_path: Path) -> None:
    builder, artifact_root = _base_builder(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    (artifact_root / "link.json").symlink_to(outside)
    with pytest.raises(ManifestError) as caught:
        builder.register_artifact(
            artifact_id="link.json",
            relative_path="link.json",
            media_type="application/json",
            public_safe=True,
        )
    _expect_code(caught, ManifestErrorCode.ARTIFACT_SYMLINK_ESCAPE)


def test_hard_linked_outside_file_is_rejected(tmp_path: Path) -> None:
    builder, artifact_root = _base_builder(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("private bytes", encoding="utf-8")
    os.link(outside, artifact_root / "linked.json")
    with pytest.raises(ManifestError) as caught:
        builder.register_artifact(
            artifact_id="linked.json",
            relative_path="linked.json",
            media_type="application/json",
            public_safe=True,
        )
    _expect_code(caught, ManifestErrorCode.ARTIFACT_PATH_UNSAFE)


def test_directory_cannot_be_registered_as_artifact(tmp_path: Path) -> None:
    builder, artifact_root = _base_builder(tmp_path)
    (artifact_root / "directory").mkdir()
    with pytest.raises(ManifestError) as caught:
        builder.register_artifact(
            artifact_id="directory.v1",
            relative_path="directory",
            media_type="application/json",
            public_safe=True,
        )
    _expect_code(caught, ManifestErrorCode.ARTIFACT_PATH_UNSAFE)


def test_duplicate_artifact_id_is_rejected(tmp_path: Path) -> None:
    builder, artifact_root = _base_builder(tmp_path)
    for name in ("one.json", "two.json"):
        (artifact_root / name).write_text(name, encoding="utf-8")
    builder.register_artifact(
        artifact_id="result.json",
        relative_path="one.json",
        media_type="application/json",
        public_safe=True,
    )
    with pytest.raises(ManifestError) as caught:
        builder.register_artifact(
            artifact_id="result.json",
            relative_path="two.json",
            media_type="application/json",
            public_safe=True,
        )
    _expect_code(caught, ManifestErrorCode.ARTIFACT_ID_DUPLICATE)


def test_duplicate_artifact_path_is_rejected(tmp_path: Path) -> None:
    builder, artifact_root = _base_builder(tmp_path)
    (artifact_root / "result.json").write_text("{}", encoding="utf-8")
    builder.register_artifact(
        artifact_id="first.json",
        relative_path="result.json",
        media_type="application/json",
        public_safe=True,
    )
    with pytest.raises(ManifestError) as caught:
        builder.register_artifact(
            artifact_id="second.json",
            relative_path="result.json",
            media_type="application/json",
            public_safe=True,
        )
    _expect_code(caught, ManifestErrorCode.ARTIFACT_PATH_DUPLICATE)


def test_missing_artifact_is_rejected(tmp_path: Path) -> None:
    builder, _ = _base_builder(tmp_path)
    with pytest.raises(ManifestError) as caught:
        builder.register_artifact(
            artifact_id="missing.json",
            relative_path="missing.json",
            media_type="application/json",
            public_safe=True,
        )
    _expect_code(caught, ManifestErrorCode.ARTIFACT_NOT_FOUND)


def test_modified_artifact_is_detected(tmp_path: Path) -> None:
    builder, artifact_root = _prepare_builder(tmp_path)
    (artifact_root / "result.json").write_text('{"changed":true}', encoding="utf-8")
    builder.start().complete(finished_at=FINISHED_AT)
    with pytest.raises(ManifestError) as caught:
        builder.finalize()
    _expect_code(caught, ManifestErrorCode.ARTIFACT_HASH_MISMATCH)


def test_repeated_finalize_reverifies_artifact_bytes(tmp_path: Path) -> None:
    builder, artifact_root = _prepare_builder(tmp_path)
    builder.start().complete(finished_at=FINISHED_AT)
    builder.finalize()
    (artifact_root / "result.json").write_text('{"changed":true}', encoding="utf-8")
    with pytest.raises(ManifestError) as caught:
        builder.finalize()
    _expect_code(caught, ManifestErrorCode.ARTIFACT_HASH_MISMATCH)


def test_repeated_identical_artifact_registration_is_idempotent(tmp_path: Path) -> None:
    builder, artifact_root = _base_builder(tmp_path)
    (artifact_root / "result.json").write_text("{}", encoding="utf-8")
    fields = {
        "artifact_id": "result.json",
        "relative_path": "result.json",
        "media_type": "application/json",
        "public_safe": True,
    }
    first = builder.register_artifact(**fields)  # type: ignore[arg-type]
    second = builder.register_artifact(**fields)  # type: ignore[arg-type]
    assert first is second
    assert len(builder.artifacts) == 1


def test_public_mode_unsafe_artifact_blocks_finalization(tmp_path: Path) -> None:
    builder, _ = _prepare_builder(tmp_path, public_safe=False)
    builder.start().complete(finished_at=FINISHED_AT)
    with pytest.raises(ManifestError) as caught:
        builder.finalize()
    _expect_code(caught, ManifestErrorCode.ARTIFACT_NOT_PUBLIC_SAFE)


def _two_artifacts(tmp_path: Path) -> tuple[RunManifestBuilder, Path]:
    builder, artifact_root = _base_builder(tmp_path)
    for name, text in (("z.json", "z"), ("a.json", "a")):
        (artifact_root / name).write_text(text, encoding="utf-8")
        builder.register_artifact(
            artifact_id=name,
            relative_path=name,
            media_type="application/json",
            public_safe=True,
        )
    return builder, artifact_root


def test_checksum_inventory_is_sorted_and_deterministic(tmp_path: Path) -> None:
    builder, _ = _two_artifacts(tmp_path)
    first = render_checksum_inventory(builder.artifacts)
    second = render_checksum_inventory(tuple(reversed(builder.artifacts)))
    assert first == second
    assert [line.split("  ", 1)[1] for line in first.decode().splitlines()] == [
        "a.json",
        "z.json",
    ]


def test_checksum_inventory_has_final_newline(tmp_path: Path) -> None:
    builder, _ = _two_artifacts(tmp_path)
    assert render_checksum_inventory(builder.artifacts).endswith(b"\n")


def test_checksum_inventory_excludes_itself(tmp_path: Path) -> None:
    artifact = ManifestArtifact.model_validate(
        {
            "artifact_id": "checksums.v1",
            "path": CHECKSUM_INVENTORY_PATH,
            "sha256": "a" * 64,
            "media_type": "text/plain",
            "public_safe": True,
        }
    )
    with pytest.raises(ManifestError) as caught:
        render_checksum_inventory((artifact,))
    _expect_code(caught, ManifestErrorCode.CHECKSUM_SELF_REFERENCE)


def test_malformed_checksum_line_is_rejected() -> None:
    with pytest.raises(ManifestError) as caught:
        parse_checksum_inventory("not-a-checksum\n")
    _expect_code(caught, ManifestErrorCode.CHECKSUM_FORMAT_INVALID)


def test_uppercase_checksum_hash_is_rejected() -> None:
    line = "A" * 64 + "  result.json\n"
    with pytest.raises(ManifestError) as caught:
        parse_checksum_inventory(line)
    _expect_code(caught, ManifestErrorCode.CHECKSUM_FORMAT_INVALID)


def test_checksum_inventory_without_final_newline_is_rejected() -> None:
    line = "a" * 64 + "  result.json"
    with pytest.raises(ManifestError) as caught:
        parse_checksum_inventory(line)
    _expect_code(caught, ManifestErrorCode.CHECKSUM_FORMAT_INVALID)


def test_duplicate_checksum_path_is_rejected() -> None:
    line = "a" * 64 + "  result.json\n"
    with pytest.raises(ManifestError) as caught:
        parse_checksum_inventory(line + line)
    _expect_code(caught, ManifestErrorCode.CHECKSUM_DUPLICATE_PATH)


def test_checksum_inventory_rejects_more_than_canonical_artifact_limit() -> None:
    content = "".join(f"{'a' * 64}  artifact-{index:03}.json\n" for index in range(201))
    with pytest.raises(ManifestError) as caught:
        parse_checksum_inventory(content)
    _expect_code(caught, ManifestErrorCode.CHECKSUM_FORMAT_INVALID)


def test_tampered_artifact_fails_checksum_verification(tmp_path: Path) -> None:
    builder, artifact_root = _two_artifacts(tmp_path)
    inventory = render_checksum_inventory(builder.artifacts)
    (artifact_root / "a.json").write_text("tampered", encoding="utf-8")
    with pytest.raises(ManifestError) as caught:
        verify_checksum_inventory(artifact_root, inventory, builder.artifacts)
    _expect_code(caught, ManifestErrorCode.CHECKSUM_VERIFICATION_FAILED)


def test_valid_checksum_inventory_verifies(tmp_path: Path) -> None:
    builder, artifact_root = _two_artifacts(tmp_path)
    content = render_checksum_inventory(builder.artifacts)
    result = verify_checksum_inventory(artifact_root, content, builder.artifacts)
    assert result.entry_count == 2
    assert result.verified_paths == ("a.json", "z.json")


def test_checksum_inventory_can_be_written_and_verified(tmp_path: Path) -> None:
    builder, artifact_root = _two_artifacts(tmp_path)
    inventory = write_checksum_inventory(artifact_root, builder.artifacts)
    assert inventory.relative_path == CHECKSUM_INVENTORY_PATH
    assert (artifact_root / CHECKSUM_INVENTORY_PATH).read_bytes() == inventory.content
    assert (
        verify_checksum_inventory(artifact_root, inventory.content, builder.artifacts).entry_count
        == 2
    )


def test_checksum_writer_does_not_create_missing_parent(tmp_path: Path) -> None:
    builder, artifact_root = _two_artifacts(tmp_path)
    missing_parent = artifact_root / "missing"
    with pytest.raises(ManifestError) as caught:
        write_checksum_inventory(
            artifact_root,
            builder.artifacts,
            checksum_relative_path="missing/checksums.sha256",
        )
    _expect_code(caught, ManifestErrorCode.CHECKSUM_FORMAT_INVALID)
    assert not missing_parent.exists()


def test_checksum_writer_rejects_symlink_parent_without_outside_write(
    tmp_path: Path,
) -> None:
    builder, artifact_root = _two_artifacts(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (artifact_root / "redirect").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ManifestError) as caught:
        write_checksum_inventory(
            artifact_root,
            builder.artifacts,
            checksum_relative_path="redirect/checksums.sha256",
        )
    _expect_code(caught, ManifestErrorCode.ARTIFACT_SYMLINK_ESCAPE)
    assert not (outside / "checksums.sha256").exists()


def test_checksum_writer_verifies_bytes_before_writing(tmp_path: Path) -> None:
    builder, artifact_root = _two_artifacts(tmp_path)
    (artifact_root / "a.json").write_text("tampered", encoding="utf-8")
    with pytest.raises(ManifestError) as caught:
        write_checksum_inventory(artifact_root, builder.artifacts)
    _expect_code(caught, ManifestErrorCode.ARTIFACT_HASH_MISMATCH)
    assert not (artifact_root / CHECKSUM_INVENTORY_PATH).exists()


def test_standalone_checksum_api_rejects_arbitrary_artifact_root(tmp_path: Path) -> None:
    artifact_root = tmp_path / "arbitrary-run" / "artifacts"
    artifact_root.mkdir(parents=True)
    (artifact_root / "result.json").write_text("{}", encoding="utf-8")
    artifact = ManifestArtifact.model_validate(
        {
            "artifact_id": "result.json",
            "path": "result.json",
            "sha256": hashlib.sha256(b"{}").hexdigest(),
            "media_type": "application/json",
            "public_safe": True,
        }
    )
    with pytest.raises(ManifestError) as caught:
        write_checksum_inventory(artifact_root, (artifact,))
    _expect_code(caught, ManifestErrorCode.ARTIFACT_PATH_UNSAFE)


def test_final_manifest_with_verified_artifacts_validates(tmp_path: Path) -> None:
    manifest, artifact_root, _ = _completed_manifest(tmp_path)
    result = verify_manifest(manifest, artifact_root=artifact_root)
    assert result.artifact_verification.verified_artifact_ids == ("result.json",)


def test_finalization_requires_at_least_one_input(tmp_path: Path) -> None:
    builder, artifact_root = _base_builder(tmp_path)
    (artifact_root / "result.json").write_text("{}", encoding="utf-8")
    builder.register_artifact(
        artifact_id="result.json",
        relative_path="result.json",
        media_type="application/json",
        public_safe=True,
    )
    builder.start().complete(finished_at=FINISHED_AT)
    with pytest.raises(ManifestError) as caught:
        builder.finalize()
    _expect_code(caught, ManifestErrorCode.MANIFEST_INPUT_INVALID)


def test_finalization_requires_at_least_one_artifact(tmp_path: Path) -> None:
    builder, _ = _base_builder(tmp_path)
    builder.register_input(
        artifact_id="fixture.v1",
        sha256=INPUT_HASH,
        classification="public_synthetic",
        row_count=3,
    )
    builder.start().complete(finished_at=FINISHED_AT)
    with pytest.raises(ManifestError) as caught:
        builder.finalize()
    _expect_code(caught, ManifestErrorCode.MANIFEST_ARTIFACT_REQUIRED)


def test_finalization_requires_terminal_status(tmp_path: Path) -> None:
    builder, _ = _prepare_builder(tmp_path)
    with pytest.raises(ManifestError) as caught:
        builder.finalize()
    _expect_code(caught, ManifestErrorCode.MANIFEST_NOT_TERMINAL)


def test_release_scan_passed_is_never_fabricated_by_builder(tmp_path: Path) -> None:
    manifest, _, builder = _completed_manifest(tmp_path)
    assert builder.release_scan_passed is False
    assert manifest.privacy.release_scan_passed is False


def test_explicit_verified_release_scan_boolean_is_preserved(tmp_path: Path) -> None:
    manifest, _, _ = _completed_manifest(tmp_path, release_scan_passed=True)
    assert manifest.privacy.release_scan_passed is True


def test_serialized_manifest_rejects_raw_rows(tmp_path: Path) -> None:
    manifest, artifact_root, _ = _completed_manifest(tmp_path)
    payload = manifest.to_canonical_dict()
    payload["raw_rows"] = [[1, 2]]
    with pytest.raises(ManifestError) as caught:
        verify_manifest(payload, artifact_root=artifact_root)
    _expect_code(caught, ManifestErrorCode.MANIFEST_SECRET_CONTENT)


def test_serialized_manifest_rejects_direct_identifier(tmp_path: Path) -> None:
    manifest, artifact_root, _ = _completed_manifest(tmp_path)
    payload = manifest.to_canonical_dict()
    payload["fallbacks"] = [
        {
            "component": "test",
            "trigger": "person" + "@" + "example.com",
            "fallback": "none",
            "honesty_label": "test",
        }
    ]
    with pytest.raises(ManifestError) as caught:
        verify_manifest(payload, artifact_root=artifact_root)
    _expect_code(caught, ManifestErrorCode.MANIFEST_SECRET_CONTENT)


def test_serialized_manifest_rejects_absolute_local_path(tmp_path: Path) -> None:
    manifest, artifact_root, _ = _completed_manifest(tmp_path)
    payload = manifest.to_canonical_dict()
    payload["fallbacks"] = [
        {
            "component": "test",
            "trigger": "/" + "Users" + "/example/private.csv",
            "fallback": "none",
            "honesty_label": "test",
        }
    ]
    with pytest.raises(ManifestError) as caught:
        verify_manifest(payload, artifact_root=artifact_root)
    _expect_code(caught, ManifestErrorCode.MANIFEST_ABSOLUTE_PATH)


def test_serialized_manifest_rejects_root_path_token(tmp_path: Path) -> None:
    manifest, artifact_root, _ = _completed_manifest(tmp_path)
    payload = manifest.to_canonical_dict()
    payload["fallbacks"] = [
        {
            "component": "test",
            "trigger": "/",
            "fallback": "none",
            "honesty_label": "test",
        }
    ]
    with pytest.raises(ManifestError) as caught:
        verify_manifest(payload, artifact_root=artifact_root)
    _expect_code(caught, ManifestErrorCode.MANIFEST_ABSOLUTE_PATH)


def test_serialized_manifest_rejects_secret(tmp_path: Path) -> None:
    manifest, artifact_root, _ = _completed_manifest(tmp_path)
    payload = manifest.to_canonical_dict()
    payload["fallbacks"] = [
        {
            "component": "test",
            "trigger": "sk-" + "B" * 16,
            "fallback": "none",
            "honesty_label": "test",
        }
    ]
    with pytest.raises(ManifestError) as caught:
        verify_manifest(payload, artifact_root=artifact_root)
    _expect_code(caught, ManifestErrorCode.MANIFEST_SECRET_CONTENT)


def test_manifest_diagnostics_are_deterministic_and_safe(tmp_path: Path) -> None:
    builder, artifact_root = _base_builder(tmp_path)
    unsafe = str(artifact_root / "missing.json")
    diagnostics = []
    for _ in range(2):
        with pytest.raises(ManifestError) as caught:
            builder.register_artifact(
                artifact_id="missing.json",
                relative_path=unsafe,
                media_type="application/json",
                public_safe=True,
            )
        diagnostics.append((caught.value.code, str(caught.value)))
        assert unsafe not in str(caught.value)
    assert diagnostics[0] == diagnostics[1]


def test_terminal_manifest_content_cannot_be_mutated(tmp_path: Path) -> None:
    manifest, _, builder = _completed_manifest(tmp_path)
    with pytest.raises(ManifestError) as caught:
        builder.register_input(
            artifact_id="other.v1",
            sha256="5" * 64,
            classification="public_synthetic",
            row_count=1,
        )
    _expect_code(caught, ManifestErrorCode.MANIFEST_INVALID_TRANSITION)
    with pytest.raises(ValidationError):
        manifest.status = RunStatus.RUNNING  # type: ignore[misc]


def test_complete_cannot_bypass_running_state(tmp_path: Path) -> None:
    builder, _ = _prepare_builder(tmp_path)
    with pytest.raises(ManifestError) as caught:
        builder.complete(finished_at=FINISHED_AT)
    _expect_code(caught, ManifestErrorCode.MANIFEST_INVALID_TRANSITION)


def test_gpt_api_other_than_responses_is_rejected(tmp_path: Path) -> None:
    artifact_root = tmp_path / RUN_ID / "artifacts"
    artifact_root.mkdir(parents=True)
    fields = {
        "run_id": RUN_ID,
        "mode": "public_builtin",
        "started_at": STARTED_AT,
        "code": {
            "repository": "riec-guard",
            "commit_sha": "a" * 40,
            "dirty": False,
            "build_week_delta_version": "1.0.0",
        },
        "environment": {
            "python": "3.12.13",
            "platform": "Darwin arm64",
            "dependency_lock_sha256": LOCK_HASH,
        },
        "contract": {
            "contract_id": "AC-ABCDEF123456",
            "sha256": CONTRACT_HASH,
            "schema_version": "1.0.0",
            "confirmation_status": "confirmed",
        },
        "registries": {
            "candidate_registry": {
                "id": "fill-structural-candidates.v1",
                "version": "1.0.0",
                "sha256": CANDIDATE_HASH,
            },
            "protocol_versions": {"H1_empirical_strict_tail": "1.0.0"},
            "action_engine_version": "1.0.0",
        },
        "randomness": {
            "global_seed": 1,
            "bootstrap_seed": 1,
            "bootstrap_replicates": 1,
        },
        "configured_model": "gpt-5.6-sol",
        "artifact_root": artifact_root,
        "storage_root_class": "public_ephemeral",
        "api": "unsupported",
    }
    with pytest.raises(ManifestError) as caught:
        RunManifestBuilder(**fields)  # type: ignore[arg-type]
    _expect_code(caught, ManifestErrorCode.MANIFEST_GPT_INVALID)


def test_manifest_error_code_registry_contains_full_frozen_set() -> None:
    assert {code.value for code in ManifestErrorCode} == {
        "MANIFEST_SCHEMA_INVALID",
        "MANIFEST_INVALID_TRANSITION",
        "MANIFEST_TIMESTAMP_INVALID",
        "MANIFEST_MODE_PRIVACY_MISMATCH",
        "MANIFEST_INPUT_INVALID",
        "MANIFEST_CONTRACT_INVALID",
        "MANIFEST_REGISTRY_INVALID",
        "MANIFEST_RANDOMNESS_INVALID",
        "MANIFEST_GPT_INVALID",
        "MANIFEST_SECRET_CONTENT",
        "MANIFEST_ABSOLUTE_PATH",
        "MANIFEST_NOT_TERMINAL",
        "MANIFEST_ARTIFACT_REQUIRED",
        "ARTIFACT_ID_DUPLICATE",
        "ARTIFACT_PATH_DUPLICATE",
        "ARTIFACT_PATH_UNSAFE",
        "ARTIFACT_NOT_FOUND",
        "ARTIFACT_SYMLINK_ESCAPE",
        "ARTIFACT_HASH_MISMATCH",
        "ARTIFACT_NOT_PUBLIC_SAFE",
        "CHECKSUM_FORMAT_INVALID",
        "CHECKSUM_DUPLICATE_PATH",
        "CHECKSUM_SELF_REFERENCE",
        "CHECKSUM_VERIFICATION_FAILED",
    }
