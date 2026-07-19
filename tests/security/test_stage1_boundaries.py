from __future__ import annotations

import copy
import json
import shutil
from collections.abc import Iterator, Mapping
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from riec_guard.contract.canonicalize import canonicalize_audit_contract
from riec_guard.contract.models import AuditContract, DatasetProfile
from riec_guard.contract.profiler import profile_dataset
from riec_guard.contract.schema_loader import SchemaKind, load_schema_registry
from riec_guard.contract.validator import validate_audit_contract
from riec_guard.domain.normalize import UploadLimits, normalize_csv_upload
from riec_guard.domain.source import SourceRepository
from riec_guard.errors import ApplicationError, ErrorCode, ErrorEnvelope
from riec_guard.evidence.ids import EvidenceError, EvidenceErrorCode, create_evidence_item
from riec_guard.evidence.models import EvidenceItem
from riec_guard.riec.registry import load_run_registry_snapshot
from riec_guard.settings import RuntimeSettings, SettingsValidationError
from riec_guard.telemetry.manifest import (
    ManifestError,
    ManifestErrorCode,
    RunManifestBuilder,
    parse_checksum_inventory,
    render_checksum_inventory,
    verify_manifest,
)
from riec_guard.telemetry.models import RunManifest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_ROOT = REPOSITORY_ROOT / "schemas" / "examples"
MANIFEST_RUN_ID = "RUN-ABCDEF123456"
REGISTRY_SNAPSHOT = load_run_registry_snapshot()
ACTION_ENGINE_VERSION = "1.0.0"

# The keys are the original TASK-013 Stage 1 security criteria. The values make the
# committed criterion-to-test mapping explicit without relying on report prose.
SECURITY_CRITERION_TESTS = {
    "S01": "test_s01_public_and_private_roots_cannot_overlap",
    "S02": "test_s02_runtime_roots_cannot_be_inside_repository",
    "S03": "test_s03_cross_run_source_access_fails",
    "S04": "test_s04_original_upload_name_never_becomes_storage_path",
    "S05": "test_s05_path_archive_binary_and_nul_uploads_are_rejected",
    "S06": "test_s06_cleanup_cannot_escape_validated_ephemeral_root",
    "S07": "test_s07_redirected_cleanup_preserves_outside_content",
    "S08": "test_s08_dataset_profile_contains_no_raw_rows",
    "S09": "test_s09_dataset_profile_contains_no_absolute_local_path",
    "S10": "test_s10_direct_identifier_examples_remain_redacted",
    "S11": "test_s11_high_cardinality_values_remain_redacted",
    "S12": "test_s12_error_envelopes_do_not_echo_malformed_values_or_duplicate_ids",
    "S13": "test_s13_contract_issues_do_not_reveal_paths_or_raw_rows",
    "S14": "test_s14_evidence_rejects_raw_row_like_keys",
    "S15": "test_s15_evidence_rejects_prompt_credential_and_path_content",
    "S16": "test_s16_manifest_rejects_prompt_credential_response_and_stack_content",
    "S17": "test_s17_artifact_records_use_only_safe_relative_posix_paths",
    "S18": "test_s18_checksum_inventory_contains_no_absolute_path",
    "S19": "test_s19_canonical_public_artifacts_contain_no_raw_rows_for_gpt",
    "S20": "test_s20_public_artifacts_never_mark_identifiers_as_sent_to_gpt",
    "S21": "test_s21_gpt_projection_schemas_are_narrower_transport_shapes",
    "S22": "test_s22_gpt_projections_have_no_contract_confirmation_authority",
}


def _repository(tmp_path: Path) -> SourceRepository:
    return SourceRepository(RuntimeSettings(ephemeral_root=tmp_path / "ephemeral-runs"))


def _profile(
    tmp_path: Path,
    payload: bytes,
    *,
    display_name: str = "public-measurements.csv",
) -> tuple[DatasetProfile | ErrorEnvelope, SourceRepository, str, str]:
    repository = _repository(tmp_path)
    run = repository.create_run()
    source = repository.register_upload(
        run.run_id,
        display_name=display_name,
        media_type="text/csv",
        payload=payload,
    )
    result = profile_dataset(repository, run_id=run.run_id, source_id=source.source_id)
    return result, repository, run.run_id, source.source_id


def _json_example(name: str) -> dict[str, Any]:
    result = json.loads((EXAMPLE_ROOT / name).read_text(encoding="utf-8"))
    assert isinstance(result, dict)
    return result


def _evidence_item(*, value: object) -> EvidenceItem:
    return create_evidence_item(
        component="PROFILE",
        kind="statistic",
        status="ok",
        statement="The public aggregate profile contains three rows.",
        value=value,
        unit=None,
        source_refs=(
            {
                "artifact_id": "public-fixture.v1",
                "artifact_sha256": "3" * 64,
                "locator": "public synthetic fixture",
            },
        ),
        parent_evidence_ids=(),
        input_sha256="1" * 64,
        contract_sha256="2" * 64,
        implementation_version="1.0.0",
        created_at="2026-07-20T00:00:00Z",
    )


def _manifest_builder(tmp_path: Path) -> tuple[RunManifestBuilder, Path]:
    artifact_root = tmp_path / MANIFEST_RUN_ID / "artifacts"
    artifact_root.mkdir(parents=True)
    builder = RunManifestBuilder(
        run_id=MANIFEST_RUN_ID,
        mode="public_builtin",
        started_at="2026-07-20T00:00:00Z",
        code={
            "repository": "riec-guard",
            "commit_sha": "a" * 40,
            "dirty": False,
            "build_week_delta_version": "1.0.0",
        },
        environment={
            "python": "3.12.13",
            "platform": "Darwin arm64",
            "dependency_lock_sha256": "1" * 64,
        },
        contract={
            "contract_id": "AC-ABCDEF123456",
            "sha256": "2" * 64,
            "schema_version": "1.0.0",
            "confirmation_status": "confirmed",
        },
        registry_snapshot=REGISTRY_SNAPSHOT,
        action_engine_version=ACTION_ENGINE_VERSION,
        randomness={
            "global_seed": 20260720,
            "bootstrap_seed": 20260720,
            "bootstrap_replicates": 200,
        },
        configured_model="gpt-5.6-sol",
        artifact_root=artifact_root,
        storage_root_class="public_ephemeral",
    )
    return builder, artifact_root


def _completed_manifest(tmp_path: Path) -> tuple[RunManifest, Path]:
    builder, artifact_root = _manifest_builder(tmp_path)
    builder.register_input(
        artifact_id="public-fixture.v1",
        sha256="3" * 64,
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
    builder.start().complete(finished_at="2026-07-20T00:01:00Z")
    return builder.finalize().manifest, artifact_root


def _walk_mapping_keys(value: object) -> Iterator[str]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if isinstance(key, str):
                yield key
            yield from _walk_mapping_keys(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _walk_mapping_keys(child)


def _walk_schema_property_names(value: object) -> Iterator[str]:
    if isinstance(value, Mapping):
        properties = value.get("properties")
        if isinstance(properties, Mapping):
            for key in properties:
                if isinstance(key, str):
                    yield key
        for child in value.values():
            yield from _walk_schema_property_names(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _walk_schema_property_names(child)


# S01 — Public and private roots cannot overlap in either direction.
def test_s01_public_and_private_roots_cannot_overlap(tmp_path: Path) -> None:
    public_root = tmp_path / "public"
    private_root = tmp_path / "private"
    for ephemeral, private in (
        (public_root / "nested", public_root),
        (private_root, private_root / "nested"),
    ):
        with pytest.raises(SettingsValidationError, match="different roots"):
            RuntimeSettings.private_local(
                ephemeral_root=ephemeral,
                private_data_root=private,
            )


# S02 — Runtime roots cannot be inside the repository.
def test_s02_runtime_roots_cannot_be_inside_repository() -> None:
    for candidate in (REPOSITORY_ROOT, REPOSITORY_ROOT / "runtime" / "attempt"):
        with pytest.raises(SettingsValidationError, match="repository root"):
            RuntimeSettings(ephemeral_root=candidate)


# S03 — Cross-run source access fails.
def test_s03_cross_run_source_access_fails(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    owner = repository.create_run()
    other = repository.create_run()
    source = repository.register_upload(
        owner.run_id,
        display_name="measurements.csv",
        media_type="text/csv",
        payload=b"quantity,group\n1,A\n2,B\n",
    )

    for access in (repository.get_source, repository.read_normalized_bytes):
        with pytest.raises(ApplicationError) as caught:
            access(other.run_id, source.source_id)
        assert caught.value.code is ErrorCode.SOURCE_NOT_FOUND
    assert repository.get_source(owner.run_id, source.source_id) == source


# S04 — Original upload filenames never become storage paths.
def test_s04_original_upload_name_never_becomes_storage_path(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    run = repository.create_run()
    display_name = "operator supplied measurements.csv"
    source = repository.register_upload(
        run.run_id,
        display_name=display_name,
        media_type="text/csv",
        payload=b"quantity\n1\n2\n",
    )

    stored_paths = (
        repository.input_path(run.run_id, source.source_id),
        repository.normalized_path(run.run_id, source.source_id),
    )
    assert source.original_display_name == display_name
    for path in stored_paths:
        assert path.parent in {run.inputs, run.normalized}
        assert path.name == f"{source.source_id}.csv"
        assert "operator" not in path.name
        assert "measurements" not in path.name


# S05 — Traversal, absolute/Windows/UNC/device paths, archives, binary and NUL fail.
def test_s05_path_archive_binary_and_nul_uploads_are_rejected() -> None:
    traversal = ".." + "/" + "private.csv"
    absolute = "/" + "var" + "/" + "private.csv"
    windows = "C" + ":" + "\\" + "private.csv"
    unc = "\\" * 2 + "server" + "\\" + "share" + "\\" + "private.csv"
    unsafe_names = (traversal, absolute, windows, unc, "CON.csv")
    for display_name in unsafe_names:
        with pytest.raises(ApplicationError) as caught:
            normalize_csv_upload(
                b"quantity\n1\n",
                display_name=display_name,
                media_type="text/csv",
                limits=UploadLimits(),
            )
        assert caught.value.code is ErrorCode.UNSAFE_DISPLAY_FILENAME

    with pytest.raises(ApplicationError) as archive_name:
        normalize_csv_upload(
            b"quantity\n1\n",
            display_name="payload.zip",
            media_type="text/csv",
            limits=UploadLimits(),
        )
    assert archive_name.value.code is ErrorCode.ARCHIVE_UPLOAD_REJECTED

    for payload, expected in (
        (b"PK\x03\x04renamed", ErrorCode.ARCHIVE_UPLOAD_REJECTED),
        (b"quantity\n\x00\n", ErrorCode.BINARY_OR_NUL_CONTENT),
        (b"quantity\n\xff\n", ErrorCode.BINARY_OR_NUL_CONTENT),
    ):
        with pytest.raises(ApplicationError) as caught:
            normalize_csv_upload(
                payload,
                display_name="renamed.csv",
                media_type="text/csv",
                limits=UploadLimits(),
            )
        assert caught.value.code is expected


# S06 — Run cleanup cannot escape its validated ephemeral root.
def test_s06_cleanup_cannot_escape_validated_ephemeral_root(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    run = repository.create_run()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("preserve", encoding="utf-8")

    invalid_run_id = ".." + "/" + outside.name
    with pytest.raises(ApplicationError) as caught:
        repository.delete_run(invalid_run_id)
    assert caught.value.code is ErrorCode.RUN_NOT_FOUND
    assert run.run_root.is_dir()
    assert sentinel.read_text(encoding="utf-8") == "preserve"


# S07 — Symlinked or redirected cleanup cannot remove outside content.
def test_s07_redirected_cleanup_preserves_outside_content(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    run = repository.create_run()
    outside = tmp_path / "outside-run"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    shutil.rmtree(run.run_root)
    try:
        run.run_root.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlinks unavailable: {type(error).__name__}")

    assert repository.delete_run(run.run_id) is True
    assert not run.run_root.exists()
    assert sentinel.read_text(encoding="utf-8") == "preserve"

    second_repository = _repository(tmp_path / "redirected")
    second_run = second_repository.create_run()
    ephemeral_root = second_run.run_root.parent
    parked_root = tmp_path / "parked-root"
    ephemeral_root.rename(parked_root)
    redirected_outside = tmp_path / "redirect-target"
    redirected_outside.mkdir()
    redirected_sentinel = redirected_outside / "sentinel.txt"
    redirected_sentinel.write_text("preserve", encoding="utf-8")
    ephemeral_root.symlink_to(redirected_outside, target_is_directory=True)

    with pytest.raises(ApplicationError) as redirected:
        second_repository.delete_run(second_run.run_id)
    assert redirected.value.code is ErrorCode.CLEANUP_FAILURE
    assert redirected_sentinel.read_text(encoding="utf-8") == "preserve"


# S08 — DatasetProfile contains no raw rows.
def test_s08_dataset_profile_contains_no_raw_rows(tmp_path: Path) -> None:
    result, _, _, _ = _profile(tmp_path, b"quantity,group\n1,A\n2,B\n3,A\n")
    assert isinstance(result, DatasetProfile)
    canonical = result.to_canonical_dict()
    assert "raw_rows" not in set(_walk_mapping_keys(canonical))
    assert result.privacy_redaction.raw_rows_included is False
    assert set(canonical) == {
        "schema_version",
        "dataset_id",
        "dataset_sha256",
        "row_count",
        "column_profiles",
        "candidate_semantic_mappings",
        "privacy_redaction",
    }


# S09 — DatasetProfile contains no absolute local path.
def test_s09_dataset_profile_contains_no_absolute_local_path(tmp_path: Path) -> None:
    result, repository, run_id, source_id = _profile(
        tmp_path,
        b"quantity,group\n1,A\n2,B\n",
        display_name="private-looking-export.csv",
    )
    assert isinstance(result, DatasetProfile)
    serialized = result.to_canonical_json()
    assert str(tmp_path) not in serialized
    assert str(repository.normalized_path(run_id, source_id)) not in serialized
    assert "private-looking-export.csv" not in serialized
    assert run_id not in serialized
    assert source_id not in serialized


# S10 — Direct-identifier examples remain redacted.
def test_s10_direct_identifier_examples_remain_redacted(tmp_path: Path) -> None:
    identifiers = (
        "stage1-alpha" + chr(64) + "example" + chr(46) + "invalid",
        "stage1-beta" + chr(64) + "example" + chr(46) + "invalid",
    )
    rows = [f"{index + 1},{identifiers[index % 2]}" for index in range(10)]
    result, _, _, _ = _profile(
        tmp_path,
        ("quantity,label\n" + "\n".join(rows) + "\n").encode(),
    )
    assert isinstance(result, DatasetProfile)
    label = result.column_profiles[1]
    assert label.safe_examples == ()
    assert label.numeric_summary is None
    assert result.privacy_redaction.direct_identifiers_included is False
    assert all(identifier not in result.to_canonical_json() for identifier in identifiers)


# S11 — High-cardinality values remain redacted.
def test_s11_high_cardinality_values_remain_redacted(tmp_path: Path) -> None:
    labels = [f"PUBLIC-CATEGORY-{index:02d}" for index in range(24)]
    rows = [f"{index + 1},{label}" for index, label in enumerate(labels)]
    result, _, _, _ = _profile(
        tmp_path,
        ("quantity,label\n" + "\n".join(rows) + "\n").encode(),
    )
    assert isinstance(result, DatasetProfile)
    label = result.column_profiles[1]
    assert label.unique_count == len(labels)
    assert label.safe_examples == ()
    assert result.privacy_redaction.high_cardinality_values_included is False
    assert all(value not in result.to_canonical_json() for value in labels)


# S12 — Error envelopes do not echo malformed values or duplicate IDs.
def test_s12_error_envelopes_do_not_echo_malformed_values_or_duplicate_ids(
    tmp_path: Path,
) -> None:
    malformed = "MALFORMED" + "-" + "VALUE" + "-" + "7421"
    malformed_result, _, _, _ = _profile(
        tmp_path / "malformed",
        f"quantity\n1\n{malformed}\n".encode(),
    )
    assert isinstance(malformed_result, ErrorEnvelope)
    assert malformed_result.code == "PROFILE_MALFORMED_NUMERIC"
    assert malformed not in malformed_result.to_canonical_json()

    duplicate = "DUPLICATE" + "-" + "ROW" + "-" + "8513"
    duplicate_result, _, _, _ = _profile(
        tmp_path / "duplicate",
        f"row_id,quantity\n{duplicate},1\n{duplicate},2\n".encode(),
    )
    assert isinstance(duplicate_result, ErrorEnvelope)
    assert duplicate_result.code == "PROFILE_DUPLICATE_ROW_ID"
    assert duplicate not in duplicate_result.to_canonical_json()


# S13 — Contract diagnostics do not reveal absolute paths or raw rows.
def test_s13_contract_issues_do_not_reveal_paths_or_raw_rows() -> None:
    profile = DatasetProfile.model_validate(_json_example("dataset_profile.example.json"))
    payload = _json_example("audit_contract.example.json")
    absolute_marker = "/" + "private" + "/" + "raw-export.csv"
    payload["column_mapping"]["quantity"]["column"] = absolute_marker
    contract = canonicalize_audit_contract(payload)

    report = validate_audit_contract(contract, profile)
    serialized = report.model_dump_json()
    assert report.blocking_errors
    assert absolute_marker not in serialized
    assert "raw-export.csv" not in serialized
    assert "raw_rows" not in set(_walk_mapping_keys(report.model_dump(mode="json")))
    assert "Traceback" not in serialized


# S14 — Evidence content rejects raw-row-like keys.
def test_s14_evidence_rejects_raw_row_like_keys() -> None:
    for key in ("raw_rows", "uploaded_rows_payload", "row_data_copy"):
        with pytest.raises(EvidenceError) as caught:
            _evidence_item(value={key: [[1, 2], [3, 4]]})
        assert caught.value.code is EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT
        assert key not in str(caught.value)


# S15 — Evidence rejects prompt-, credential-, and path-like sensitive content.
def test_s15_evidence_rejects_prompt_credential_and_path_content() -> None:
    absolute_path = "/" + "private" + "/" + "source.csv"
    secret = "sk-" + "A" * 16
    cases = (
        ({"prompt": "confidential request body"}, "confidential request body"),
        ({"api" + "_key": secret}, secret),
        ({"note": absolute_path}, absolute_path),
    )
    for value, marker in cases:
        with pytest.raises(EvidenceError) as caught:
            _evidence_item(value=value)
        assert caught.value.code is EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT
        assert marker not in str(caught.value)


# S16 — Manifest rejects prompts/messages, credentials, response bodies and stack traces.
def test_s16_manifest_rejects_prompt_credential_response_and_stack_content(
    tmp_path: Path,
) -> None:
    manifest, artifact_root = _completed_manifest(tmp_path)
    secret = "sk-" + "B" * 16
    cases: tuple[tuple[str, object, str, ManifestErrorCode], ...] = (
        (
            "prompt",
            "confidential request body",
            "confidential request body",
            ManifestErrorCode.MANIFEST_SECRET_CONTENT,
        ),
        (
            "messages",
            ["private message body"],
            "private message body",
            ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
        ),
        ("api" + "_key", secret, secret, ManifestErrorCode.MANIFEST_SECRET_CONTENT),
        (
            "response_body",
            "private response body",
            "private response body",
            ManifestErrorCode.MANIFEST_SCHEMA_INVALID,
        ),
        (
            "stack_trace",
            "Trace" + "back: private failure",
            "private failure",
            ManifestErrorCode.MANIFEST_SECRET_CONTENT,
        ),
    )
    for key, value, marker, expected_code in cases:
        payload = copy.deepcopy(manifest.to_canonical_dict())
        gpt = payload["gpt"]
        assert isinstance(gpt, dict)
        gpt[key] = value
        with pytest.raises(ManifestError) as caught:
            verify_manifest(
                payload,
                artifact_root=artifact_root,
                expected_registry_snapshot=REGISTRY_SNAPSHOT,
                expected_action_engine_version=ACTION_ENGINE_VERSION,
            )
        assert caught.value.code is expected_code
        assert marker not in str(caught.value)


# S17 — Artifact records contain only safe relative POSIX paths.
def test_s17_artifact_records_use_only_safe_relative_posix_paths(tmp_path: Path) -> None:
    builder, artifact_root = _manifest_builder(tmp_path)
    nested = artifact_root / "nested"
    nested.mkdir()
    artifact_file = nested / "result.json"
    artifact_file.write_text("{}", encoding="utf-8")
    artifact = builder.register_artifact(
        artifact_id="result.json",
        relative_path="nested/result.json",
        media_type="application/json",
        public_safe=True,
    )
    path = PurePosixPath(artifact.path)
    assert artifact.path == "nested/result.json"
    assert not path.is_absolute()
    assert ".." not in path.parts
    assert "\\" not in artifact.path
    assert str(tmp_path) not in artifact.path

    with pytest.raises(ManifestError) as caught:
        builder.register_artifact(
            artifact_id="absolute.json",
            relative_path=str(artifact_file.resolve()),
            media_type="application/json",
            public_safe=True,
        )
    assert caught.value.code is ManifestErrorCode.ARTIFACT_PATH_UNSAFE


# S18 — Checksum inventory contains no absolute path.
def test_s18_checksum_inventory_contains_no_absolute_path(tmp_path: Path) -> None:
    builder, artifact_root = _manifest_builder(tmp_path)
    for name, content in (("z.json", "z"), ("a.json", "a")):
        (artifact_root / name).write_text(content, encoding="utf-8")
        builder.register_artifact(
            artifact_id=name,
            relative_path=name,
            media_type="application/json",
            public_safe=True,
        )

    inventory = render_checksum_inventory(builder.artifacts)
    entries = parse_checksum_inventory(inventory)
    assert tuple(entry.path for entry in entries) == ("a.json", "z.json")
    assert str(tmp_path).encode() not in inventory
    assert all(not PurePosixPath(entry.path).is_absolute() for entry in entries)
    assert all("\\" not in entry.path and ":" not in entry.path for entry in entries)


# S19 — Canonical public artifacts contain no raw rows intended for GPT.
def test_s19_canonical_public_artifacts_contain_no_raw_rows_for_gpt(tmp_path: Path) -> None:
    profile_result, _, _, _ = _profile(
        tmp_path / "profile",
        b"quantity,group\n1,A\n2,B\n3,A\n",
    )
    assert isinstance(profile_result, DatasetProfile)
    contract = AuditContract.model_validate(_json_example("audit_contract.example.json"))
    evidence = _evidence_item(value={"n_rows": 3, "mean": 2.0})
    manifest, _ = _completed_manifest(tmp_path / "manifest")
    artifacts = (
        profile_result.to_canonical_dict(),
        contract.to_canonical_dict(),
        evidence.to_canonical_dict(),
        manifest.to_canonical_dict(),
    )
    for artifact in artifacts:
        assert "raw_rows" not in set(_walk_mapping_keys(artifact))
    assert profile_result.privacy_redaction.raw_rows_included is False
    assert contract.privacy.raw_rows_to_gpt is False
    assert manifest.privacy.raw_rows_sent_to_gpt is False


# S20 — Canonical public artifacts never mark direct identifiers as sent to GPT.
def test_s20_public_artifacts_never_mark_identifiers_as_sent_to_gpt(tmp_path: Path) -> None:
    profile_result, _, _, _ = _profile(tmp_path / "profile", b"quantity\n1\n2\n")
    assert isinstance(profile_result, DatasetProfile)
    contract = AuditContract.model_validate(_json_example("audit_contract.example.json"))
    manifest, _ = _completed_manifest(tmp_path / "manifest")

    assert profile_result.privacy_redaction.direct_identifiers_included is False
    assert contract.privacy.direct_identifiers_to_gpt is False
    assert manifest.privacy.direct_identifiers_sent_to_gpt is False


# S21 — GPT projection schemas remain narrower than canonical persisted schemas.
def test_s21_gpt_projection_schemas_are_narrower_transport_shapes() -> None:
    registry = load_schema_registry()
    canonical_names = {record.logical_name for record in registry.canonical()}
    projection_names = {record.logical_name for record in registry.gpt_projections()}
    assert len(canonical_names) == 11
    assert len(projection_names) == 3
    assert canonical_names.isdisjoint(projection_names)

    for projection in registry.gpt_projections():
        target = registry.promotion_target(projection.logical_name)
        projection_schema = projection.validation_schema()
        target_schema = target.validation_schema()
        assert projection.kind is SchemaKind.GPT_PROJECTION
        assert target.kind is SchemaKind.CANONICAL
        assert projection.promotes_to == target.logical_name
        assert projection_schema.get("additionalProperties") is False
        assert len(projection_schema.get("properties", {})) < len(
            target_schema.get("properties", {})
        )
        assert not Draft202012Validator(target_schema).is_valid(projection.example())
        assert not Draft202012Validator(projection_schema).is_valid(target.example())


# S22 — GPT projections do not introduce canonical confirmation authority.
def test_s22_gpt_projections_have_no_contract_confirmation_authority() -> None:
    registry = load_schema_registry()
    forbidden_authority = {
        "analysis_permitted",
        "confirmation",
        "confirmation_status",
        "confirmed_at",
        "confirmed_by",
        "confirmed_fields",
        "contract_id",
    }
    for projection in registry.gpt_projections():
        properties = set(_walk_schema_property_names(projection.validation_schema()))
        assert properties.isdisjoint(forbidden_authority)

    draft_schema = registry.lookup("gpt_audit_contract_draft").validation_schema()
    confirmed = draft_schema["properties"]["column_mapping"]["items"]["properties"]["confirmed"]
    assert confirmed == {"const": False}
    draft_example = registry.lookup("gpt_audit_contract_draft").example()
    assert all(mapping["confirmed"] is False for mapping in draft_example["column_mapping"])
