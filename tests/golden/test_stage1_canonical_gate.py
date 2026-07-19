from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from riec_guard.contract.canonicalize import (
    CONFIRMATION_FIELD_ORDER,
    canonicalize_audit_contract,
    compute_contract_hash,
)
from riec_guard.contract.models import (
    CANONICAL_MODEL_REGISTRY,
    AuditContract,
    ConfirmedBy,
    DatasetProfile,
    get_canonical_model,
)
from riec_guard.contract.profiler import profile_dataset
from riec_guard.contract.schema_loader import load_schema_registry
from riec_guard.contract.validator import (
    analysis_is_permitted,
    confirm_audit_contract,
    validate_audit_contract,
)
from riec_guard.domain.source import SourceRepository
from riec_guard.errors import ErrorEnvelope
from riec_guard.evidence.ids import verify_evidence_item
from riec_guard.evidence.ledger import EvidenceLedgerBuilder, verify_ledger
from riec_guard.evidence.models import (
    EvidenceComponent,
    EvidenceKind,
    EvidenceLedger,
    EvidenceStatus,
)
from riec_guard.riec.registry import load_run_registry_snapshot
from riec_guard.settings import RuntimeSettings
from riec_guard.telemetry.manifest import (
    RunManifestBuilder,
    manifest_sha256,
    render_checksum_inventory,
    verify_checksum_inventory,
    verify_manifest,
)
from riec_guard.telemetry.models import RunManifest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "stage1"
SCHEMA_ROOT = REPOSITORY_ROOT / "schemas"
EXAMPLE_ROOT = SCHEMA_ROOT / "examples"
RUN_ID = "RUN-A1B2C3D4E5F6"
ACTION_ENGINE_VERSION = "1.0.0"
LOCK_HASH = "82116ddca67ef3da9b8bbf54942eb186cfcf6ace0b284dfdeabba9644effb76e"
FROZEN_CONTRACT_HASH = "84e73f9b8fb08527de0e976958b1aa83b2bf78f25990ceb6fe86930c7479b6dd"
FROZEN_LEDGER_HASH = "b533abc49c9438e59ed493e94b6c855b41bd8e87ab7e0646411d951dc06c9ca7"
FROZEN_MANIFEST_HASH = "b4d580adf97b38c32abaca9f195502ab838bb591dad11f3c23475de5b2c16700"
FROZEN_REGISTRY_HASH = "3adcf2fedebc515497b24bb0eae2b51af9af4bc4bf55556a0d9e375008ed9bf2"

FIXTURE_HASHES = {
    "checksums.sha256": "ab49773c5705d725f352b7c455894eeea18ffc9e43f60fa25acaf876fa5357e0",
    "confirmed_contract.json": "b8a251e9b41568e0f0e61c8052340e0586b105a869912d7a446d99d9d54e1e6c",
    "dataset_profile.json": "b88594bb554beaeb5b95d66a22094fed5b7bae29b857f20ee6306e1862d76e06",
    "draft_contract.json": "7aa0e713aacea52e964a83b6a2d3eee50361bd61ee2e4d450bff3d53ca2f56a7",
    "draft_contract_input.json": "a7e3f2d8a7702e9948933747fc6b71f95e2d4f1e135a8ededdd1d54e09a0fbb0",
    "error_envelope.json": "647f862b2a6dd0087b7fb6cf931f1d4937cb7eb2ee231f52b6a2564bb3cbc019",
    "evidence_ledger.json": "e22327c7045331bdd62e41f769480c6fec76a82c4c952d0a540ee6b118922943",
    "expectations.json": "338456b7857b4b60b05a6d44f6b7edb8a5286f2d560a4dbe5db5c5922ab3eba1",
    "normalized.csv": "3445e18cc213d4726e4d39d73226573822f6129c142b4cd5ee652134316ebf83",
    "registry_snapshot.json": "1a26751609ef141d2eacb8345b2e91f854c4c6d3bef1e87c6a2afc0b885fbcf2",
    "run_manifest.json": "dfe29b88c5d6d348672759c4c1c3a376bc4e86a1df1e529cae5e5ccf1ed2f17e",
}

SCHEMA_HASHES = {
    "canonical/ACTION_DECISION_SCHEMA.json": "b128078423c68a57858cf3977eaf73332e2aa2f0bb59330870912c1920594a42",
    "canonical/AUDIT_CONTRACT_SCHEMA.json": "4433d0e982b42bc2b264ac7865a529dc00a53625b81c7047e8140a15736e62c8",
    "canonical/CANDIDATE_REGISTRY_SCHEMA.json": "eb2ba147531777d33ecea1a1115789e025b2a38ac7061fffc611095b143cc1cb",
    "canonical/CLAIM_AUDIT_SCHEMA.json": "d269d52db54d4208810a05c0b0a76a48a30e1e96161d3643f31e3c47562b3942",
    "canonical/DATASET_PROFILE_SCHEMA.json": "31ef9c50252ea742d519183040e36f50adca0deab6003b813b2541a432617f77",
    "canonical/ERROR_ENVELOPE_SCHEMA.json": "0eb7dd2fd9e28721261a77691acff727df0326655d4e673af618d90f3b25fa4b",
    "canonical/EVIDENCE_LEDGER_SCHEMA.json": "9e1837900ad86720ae687cf8f8255db1017cc2aafc0674c8d2e058b5f1a11385",
    "canonical/PROTOCOL_RESULT_SCHEMA.json": "9733dd8b6c7c462c0028949ba6169173915d15773192c0f0d0f554e82a612f92",
    "canonical/REPORT_DRAFT_SCHEMA.json": "35b06dabf7426640130b163c7c07fd57044a5f666ba0ad99be20a0e6222e49b8",
    "canonical/RIEC_SELECTION_SCHEMA.json": "4adc8f166e5e5e46082a761bfc9b99dac04904a61243301c2b5bee910f8a5ec4",
    "canonical/RUN_MANIFEST_SCHEMA.json": "ee06b78bf885b28726b73f5e273db35ee90e1706e4b82f73dc8d66179b8649fa",
    "gpt/GPT_AUDIT_CONTRACT_DRAFT_SCHEMA.json": "625b46c6b441bf51b2ca42977e6cb14df1e05cb7a9600d7a239800badcd389f4",
    "gpt/GPT_CLAIM_AUDIT_SCHEMA.json": "3a8b556c736fffdf12ec7368c25fe71a0ec2e204f26ea31a80229b2e4ade8660",
    "gpt/GPT_REPORT_DRAFT_SCHEMA.json": "aab7e4147944679dbbc93e6754b646e912f8dbfd08c939070391dc5c0ffe20cd",
}

EXAMPLE_HASHES = {
    "action_decision.example.json": "ef40b0059d6bdd4e8b2b0090dba442c8911d6026ecaaa7a145afdbe553d87527",
    "audit_contract.example.json": "8f3218f9c476a534c7a1c6f4cc453f61d292f18a9041192ef889f33bcf142f2d",
    "candidate_registry.example.json": "52ef523ad14e3366af88251ce2831f5da69db3a7641e18af9979313985f8b2d3",
    "claim_audit.example.json": "18bd4e4f854e1d73ec1a65f66ae8a651343d71f3a5d027982720818e0e812da2",
    "dataset_profile.example.json": "161205435dfd43d7002599a18fdffefc2e6b76ce18825839c8c64d2e8d417637",
    "error_envelope.example.json": "5d354f60f08082779c4a31507990d34468cd2baffa233b6751b05b6f4d880cdb",
    "evidence_ledger.example.json": "a1f4df9c7d782cff7e61b27d839d422d0e59b37ba0b70e9d4026682d350d2b41",
    "gpt_audit_contract_draft.example.json": "1fcdc8bac2aa98beb614ad5d6ee026f838963b89ce4f734e095b2156246ec2f0",
    "gpt_claim_audit.example.json": "985e34f3af3f4db048734442f560a094ff6fe7a3505f39a1c68e158331ff2894",
    "gpt_report_draft.example.json": "7d882f06d9d57457ab3ab646e1286e50ed7b2988583ebdf0297dcc45eb30afbe",
    "protocol_results.example.json": "78fecd8f27b27b824793c4626e5d964e2bb24b75402070fe7944ba4a8aa35e4c",
    "report_draft.example.json": "84db7dfbfe33207501dcc251096528d31d1e45e19de475d755b93cccb38d2854",
    "riec_selection.example.json": "a1e74c10bcda55479022cfa60773401d26129445af86488b556d30abbc59fc02",
    "run_manifest.example.json": "b2f99e310e14c8cf331149b7af077f522549eb958c221ac2d1073c752cf036c8",
}

RUNTIME_ARTIFACTS = (
    ("normalized.csv", "text/csv"),
    ("dataset_profile.json", "application/json"),
    ("draft_contract_input.json", "application/json"),
    ("draft_contract.json", "application/json"),
    ("confirmed_contract.json", "application/json"),
    ("registry_snapshot.json", "application/json"),
    ("evidence_ledger.json", "application/json"),
    ("error_envelope.json", "application/json"),
)


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _expectations() -> dict[str, Any]:
    return _json(FIXTURE_ROOT / "expectations.json")


def _append_stage1_evidence(
    builder: EvidenceLedgerBuilder,
    *,
    profile: DatasetProfile,
    confirmed: AuditContract,
    registry_hash: str,
) -> None:
    fixture_hashes = _expectations()["fixture_sha256"]
    assert isinstance(fixture_hashes, dict)
    contract_hash = compute_contract_hash(confirmed).canonical_contract_sha256
    profile_record = builder.append_new(
        component=EvidenceComponent.PROFILE,
        kind=EvidenceKind.PROVENANCE,
        status=EvidenceStatus.OK,
        statement="The Stage 1 public synthetic dataset profile is deterministic and redacted.",
        value={
            "dataset_id": profile.dataset_id,
            "row_count": profile.row_count,
            "deployment_group_count": 8,
            "redaction_verified": True,
        },
        unit=None,
        source_refs=(
            {
                "artifact_id": "normalized.csv",
                "artifact_sha256": fixture_hashes["normalized.csv"],
                "locator": "public synthetic normalized fixture",
            },
        ),
        parent_evidence_ids=(),
        input_sha256=profile.dataset_sha256,
        contract_sha256=contract_hash,
        implementation_version="task-013-stage1-golden-1.0.0",
        created_at="2026-07-20T00:02:00Z",
    )
    contract_record = builder.append_new(
        component=EvidenceComponent.CONTRACT,
        kind=EvidenceKind.PROVENANCE,
        status=EvidenceStatus.OK,
        statement="The explicit confirmed AuditContract permits pre-statistics analysis entry.",
        value={
            "contract_id": confirmed.contract_id,
            "analysis_permitted": True,
            "g1_eligible": True,
        },
        unit=None,
        source_refs=(
            {
                "artifact_id": "confirmed_contract.json",
                "artifact_sha256": fixture_hashes["confirmed_contract.json"],
                "locator": confirmed.contract_id,
            },
        ),
        parent_evidence_ids=(profile_record.item.evidence_id,),
        input_sha256=profile.dataset_sha256,
        contract_sha256=contract_hash,
        implementation_version="task-013-stage1-golden-1.0.0",
        created_at="2026-07-20T00:02:00Z",
    )
    builder.append_new(
        component=EvidenceComponent.SYSTEM,
        kind=EvidenceKind.PROVENANCE,
        status=EvidenceStatus.OK,
        statement="The run uses the five frozen Stage 1 configuration snapshots.",
        value={
            "config_count": 5,
            "combined_canonical_sha256": registry_hash,
            "all_frozen": True,
        },
        unit=None,
        source_refs=(
            {
                "artifact_id": "registry_snapshot.json",
                "artifact_sha256": fixture_hashes["registry_snapshot.json"],
                "locator": "five immutable configuration identities",
            },
        ),
        parent_evidence_ids=(contract_record.item.evidence_id,),
        input_sha256=profile.dataset_sha256,
        contract_sha256=contract_hash,
        implementation_version="task-013-stage1-golden-1.0.0",
        created_at="2026-07-20T00:02:00Z",
    )


def _run_stage1_chain(runtime_root: Path) -> dict[str, object]:
    runtime_root = runtime_root.resolve()
    normalized = (FIXTURE_ROOT / "normalized.csv").read_bytes()
    repository = SourceRepository(RuntimeSettings(ephemeral_root=runtime_root / "source-runtime"))
    source_run = repository.create_run()
    source = repository.register_built_in(
        source_run.run_id,
        built_in_key="stable_symmetric",
        display_name="Stage 1 public synthetic",
        payload=normalized,
    )
    profile = profile_dataset(repository, run_id=source_run.run_id, source_id=source.source_id)
    assert isinstance(profile, DatasetProfile)
    assert repository.read_normalized_bytes(source_run.run_id, source.source_id) == normalized
    assert profile.to_canonical_dict() == _json(FIXTURE_ROOT / "dataset_profile.json")

    draft = canonicalize_audit_contract(_json(FIXTURE_ROOT / "draft_contract_input.json"))
    assert draft.to_canonical_dict() == _json(FIXTURE_ROOT / "draft_contract.json")
    draft_report = validate_audit_contract(draft, profile)
    assert draft_report.valid and not analysis_is_permitted(draft_report)
    transition = confirm_audit_contract(
        draft,
        profile,
        confirmed_fields=CONFIRMATION_FIELD_ORDER,
        confirmed_by=ConfirmedBy.VERSIONED_BUILTIN,
        confirmed_at="2026-07-20T00:01:00Z",
    )
    assert transition.transitioned
    confirmed = transition.contract
    assert confirmed.to_canonical_dict() == _json(FIXTURE_ROOT / "confirmed_contract.json")
    confirmed_report = validate_audit_contract(confirmed, profile)
    assert analysis_is_permitted(confirmed_report) and confirmed_report.g1_eligible

    snapshot = load_run_registry_snapshot()
    registry_fixture = _json(FIXTURE_ROOT / "registry_snapshot.json")
    assert list(snapshot.provenance_records()) == registry_fixture["configs"]
    assert snapshot.combined_canonical_sha256 == registry_fixture["combined_canonical_sha256"]

    ledger_builder = EvidenceLedgerBuilder(RUN_ID)
    _append_stage1_evidence(
        ledger_builder,
        profile=profile,
        confirmed=confirmed,
        registry_hash=snapshot.combined_canonical_sha256,
    )
    ledger = ledger_builder.finalize()
    assert ledger.to_canonical_dict() == _json(FIXTURE_ROOT / "evidence_ledger.json")
    ledger_verification = verify_ledger(
        ledger,
        expected_run_id=RUN_ID,
        bound_items=ledger_builder.bound_items,
    )
    assert ledger_verification.run_ownership_verified
    assert ledger_verification.graph.node_count == 3
    assert ledger_verification.graph.edge_count == 2

    artifact_root = runtime_root / RUN_ID / "artifacts"
    artifact_root.mkdir(parents=True)
    for name, _ in RUNTIME_ARTIFACTS:
        shutil.copyfile(FIXTURE_ROOT / name, artifact_root / name)
    manifest_builder = RunManifestBuilder(
        run_id=RUN_ID,
        mode="public_builtin",
        started_at="2026-07-20T00:00:00Z",
        code={
            "repository": "riec-guard",
            "commit_sha": "1e267b51715505e8598dd87714dd50535e01bf29",
            "dirty": False,
            "build_week_delta_version": "task-013-stage1-golden-1.0.0",
        },
        environment={
            "python": "3.12.13",
            "platform": "platform-independent-golden",
            "dependency_lock_sha256": LOCK_HASH,
        },
        contract={
            "contract_id": confirmed.contract_id,
            "sha256": compute_contract_hash(confirmed).canonical_contract_sha256,
            "schema_version": "1.0.0",
            "confirmation_status": "confirmed",
        },
        registry_snapshot=snapshot,
        action_engine_version=ACTION_ENGINE_VERSION,
        randomness={
            "global_seed": 20260718,
            "bootstrap_seed": 20260718,
            "bootstrap_replicates": 200,
        },
        configured_model="gpt-5.6-sol",
        artifact_root=artifact_root,
        storage_root_class="public_ephemeral",
        release_scan_passed=False,
        store=False,
    )
    manifest_builder.register_input(
        artifact_id="stage1-public-synthetic.v1",
        sha256=profile.dataset_sha256,
        classification="public_synthetic",
        row_count=profile.row_count,
    )
    for name, media_type in RUNTIME_ARTIFACTS:
        manifest_builder.register_artifact(
            artifact_id=name,
            relative_path=name,
            media_type=media_type,
            public_safe=True,
        )
    manifest_builder.start().complete(finished_at="2026-07-20T00:03:00Z")
    manifest = manifest_builder.finalize().manifest
    assert manifest.to_canonical_dict() == _json(FIXTURE_ROOT / "run_manifest.json")
    manifest_verification = verify_manifest(
        manifest,
        artifact_root=artifact_root,
        expected_registry_snapshot=snapshot,
        expected_action_engine_version=ACTION_ENGINE_VERSION,
    )
    inventory = render_checksum_inventory(manifest.artifacts)
    assert inventory == (FIXTURE_ROOT / "checksums.sha256").read_bytes()
    checksum_verification = verify_checksum_inventory(
        artifact_root,
        inventory,
        manifest.artifacts,
    )

    return {
        "profile": profile.to_canonical_json(),
        "draft": draft.to_canonical_json(),
        "confirmed": confirmed.to_canonical_json(),
        "registry": snapshot.combined_canonical_sha256,
        "ledger": ledger.to_canonical_json(),
        "ledger_sha256": ledger_verification.ledger_canonical_sha256,
        "manifest": manifest.to_canonical_json(),
        "manifest_sha256": manifest_verification.manifest_sha256,
        "inventory": inventory,
        "inventory_sha256": checksum_verification.inventory_sha256,
    }


def test_stage1_fixture_inventory_is_complete_and_byte_frozen() -> None:
    observed = {path.name: _sha256(path) for path in FIXTURE_ROOT.iterdir() if path.is_file()}
    assert observed == FIXTURE_HASHES
    expected_embedded = dict(FIXTURE_HASHES)
    expected_embedded.pop("expectations.json")
    assert _expectations()["fixture_sha256"] == expected_embedded


def test_registered_schema_model_example_and_byte_integrity_is_frozen() -> None:
    registry = load_schema_registry()
    assert len(registry.canonical()) == len(CANONICAL_MODEL_REGISTRY) == 11
    assert len(registry.gpt_projections()) == 3
    assert set(CANONICAL_MODEL_REGISTRY) == {record.logical_name for record in registry.canonical()}
    for record in (*registry.canonical(), *registry.gpt_projections()):
        Draft202012Validator(
            record.validation_schema(),
            format_checker=FormatChecker(),
        ).validate(record.example())
    for record in registry.canonical():
        model = get_canonical_model(record.logical_name).model_validate(record.example())
        assert model.to_canonical_dict() == record.example()
    assert {_path: _sha256(SCHEMA_ROOT / _path) for _path in SCHEMA_HASHES} == SCHEMA_HASHES
    assert {_path: _sha256(EXAMPLE_ROOT / _path) for _path in EXAMPLE_HASHES} == EXAMPLE_HASHES
    assert _sha256(SCHEMA_ROOT / "SCHEMA_INDEX.json") == (
        "e88012d093c2d06962930292bb9716a539cc7e2984e15438847022eabd30aacc"
    )
    assert _sha256(REPOSITORY_ROOT / "requirements.lock") == LOCK_HASH


def test_frozen_contract_evidence_manifest_and_registry_identities_remain_exact() -> None:
    contract = AuditContract.model_validate(_json(EXAMPLE_ROOT / "audit_contract.example.json"))
    contract_identity = compute_contract_hash(contract)
    assert contract_identity.contract_id == contract.contract_id == "AC-84E73F9B8FB0"
    assert contract_identity.canonical_contract_sha256 == FROZEN_CONTRACT_HASH

    ledger = EvidenceLedger.model_validate(_json(EXAMPLE_ROOT / "evidence_ledger.example.json"))
    for item in ledger.items:
        identity = verify_evidence_item(item)
        assert identity.evidence_id == item.evidence_id
        assert identity.content_sha256 == item.content_sha256
    ledger_verification = verify_ledger(ledger)
    assert ledger_verification.item_count == 11
    assert ledger_verification.ledger_canonical_sha256 == FROZEN_LEDGER_HASH

    manifest = RunManifest.model_validate(_json(EXAMPLE_ROOT / "run_manifest.example.json"))
    assert manifest_sha256(manifest) == FROZEN_MANIFEST_HASH
    assert load_run_registry_snapshot().combined_canonical_sha256 == FROZEN_REGISTRY_HASH


def test_stage1_committed_canonical_fixtures_validate_and_are_internally_bound() -> None:
    expectations = _expectations()
    profile = DatasetProfile.model_validate(_json(FIXTURE_ROOT / "dataset_profile.json"))
    draft = AuditContract.model_validate(_json(FIXTURE_ROOT / "draft_contract.json"))
    confirmed = AuditContract.model_validate(_json(FIXTURE_ROOT / "confirmed_contract.json"))
    error = ErrorEnvelope.model_validate(_json(FIXTURE_ROOT / "error_envelope.json"))
    ledger = EvidenceLedger.model_validate(_json(FIXTURE_ROOT / "evidence_ledger.json"))
    manifest = RunManifest.model_validate(_json(FIXTURE_ROOT / "run_manifest.json"))

    assert profile.dataset_sha256 == _sha256(FIXTURE_ROOT / "normalized.csv")
    assert expectations["dataset"] == {
        "dataset_id": profile.dataset_id,
        "dataset_sha256": profile.dataset_sha256,
        "row_count": profile.row_count,
    }
    assert expectations["contracts"]["draft"]["canonical_sha256"] == (
        compute_contract_hash(draft).canonical_contract_sha256
    )
    assert expectations["contracts"]["confirmed"]["canonical_sha256"] == (
        compute_contract_hash(confirmed).canonical_contract_sha256
    )
    ledger_verification = verify_ledger(ledger)
    assert expectations["evidence"]["ledger_canonical_sha256"] == (
        ledger_verification.ledger_canonical_sha256
    )
    assert expectations["manifest"]["canonical_sha256"] == manifest_sha256(manifest)
    assert ledger.run_id == manifest.run_id == RUN_ID
    assert manifest.contract.contract_id == confirmed.contract_id
    assert manifest.contract.sha256 == compute_contract_hash(confirmed).canonical_contract_sha256
    assert {item.contract_sha256 for item in ledger.items} == {manifest.contract.sha256}
    assert {item.input_sha256 for item in ledger.items} == {profile.dataset_sha256}
    manifest_artifacts = {artifact.artifact_id for artifact in manifest.artifacts}
    assert all(
        source.artifact_id in manifest_artifacts
        for item in ledger.items
        for source in item.source_refs
    )
    assert tuple(item.component for item in ledger.items) == (
        EvidenceComponent.PROFILE,
        EvidenceComponent.CONTRACT,
        EvidenceComponent.SYSTEM,
    )
    assert manifest.gpt.calls == ()
    assert not manifest.privacy.release_scan_passed
    assert error.safe_details == {"column_index": 0, "malformed_count": 1}


def test_stage1_public_pre_statistics_chain_matches_golden_twice(tmp_path: Path) -> None:
    first = _run_stage1_chain(tmp_path / "first")
    second = _run_stage1_chain(tmp_path / "second")
    assert first == second
    expectations = _expectations()
    assert first["ledger_sha256"] == expectations["evidence"]["ledger_canonical_sha256"]
    assert first["manifest_sha256"] == expectations["manifest"]["canonical_sha256"]
    assert first["inventory_sha256"] == FIXTURE_HASHES["checksums.sha256"]
