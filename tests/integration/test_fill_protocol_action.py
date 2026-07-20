from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from riec_guard.app_service import AuditService, FillProtocolActionResult
from riec_guard.contract.canonicalize import canonicalize_audit_contract
from riec_guard.contract.models import (
    ActionDecision,
    ActionState,
    AuditContract,
    DatasetProfile,
    HeadroomBasis,
)
from riec_guard.contract.profiler import profile_dataset
from riec_guard.contract.schema_loader import load_schema_registry
from riec_guard.domain.source import SourceRepository
from riec_guard.evidence.ids import canonical_sha256, verify_evidence_item
from riec_guard.evidence.ledger import EvidenceLedgerBuilder
from riec_guard.evidence.models import EvidenceComponent
from riec_guard.riec.registry import load_run_registry_snapshot
from riec_guard.settings import RuntimeSettings

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = REPOSITORY_ROOT / "tests" / "golden" / "fixtures" / "stage1"


def test_safe_fill_service_emits_canonical_artifacts_and_aggregate_lineage(
    tmp_path: Path,
) -> None:
    normalized = (FIXTURE_ROOT / "normalized.csv").read_bytes()
    repository = SourceRepository(RuntimeSettings(ephemeral_root=tmp_path / "runtime"))
    run = repository.create_run()
    source = repository.register_built_in(
        run.run_id,
        built_in_key="macro02_stage1",
        display_name="Macro 02 public synthetic",
        payload=normalized,
    )
    profile = profile_dataset(repository, run_id=run.run_id, source_id=source.source_id)
    assert isinstance(profile, DatasetProfile)
    contract = AuditContract.model_validate_json(
        (FIXTURE_ROOT / "confirmed_contract.json").read_text(encoding="utf-8")
    )
    artifact_run_id = f"RUN-{run.run_id[4:16].upper()}"
    builder = EvidenceLedgerBuilder(artifact_run_id)

    result = AuditService().run_audit(
        repository,
        run_id=run.run_id,
        source_id=source.source_id,
        contract=contract,
        dataset_profile=profile,
        registry_snapshot=load_run_registry_snapshot(),
        evidence_builder=builder,
    )

    assert isinstance(result, FillProtocolActionResult), getattr(result, "code", None)
    assert result.riec.artifact_run_id == artifact_run_id
    assert result.protocols.run_id == artifact_run_id
    assert result.action.run_id == artifact_run_id
    assert len(builder.items) == 3
    assert not builder.finalized
    assert tuple(item.component for item in builder.items) == (
        EvidenceComponent.RIEC,
        EvidenceComponent.PROTOCOL,
        EvidenceComponent.ACTION,
    )
    assert result.protocol_evidence.parent_evidence_ids == (result.riec.evidence_item.evidence_id,)
    assert set(result.action_evidence.parent_evidence_ids) == {
        result.riec.evidence_item.evidence_id,
        result.protocol_evidence.evidence_id,
    }
    verify_evidence_item(result.protocol_evidence)
    verify_evidence_item(result.action_evidence)

    assert tuple(item.protocol_id.value for item in result.protocols.results) == (
        "D0_mean_diagnostic",
        "H1_group_empirical_quantile",
        "H2_gaussian_residual_tail",
        "H3_student_t_residual_tail",
        "U1_group_bootstrap_bound",
        "G1_ordered_stability_screen",
        "G2_evidence_sufficiency_gate",
    )
    assert all(
        item.evidence_ids == (result.protocol_evidence.evidence_id,)
        for item in result.protocols.results
    )
    assert result.action.state is ActionState.INSUFFICIENT_EVIDENCE
    assert result.action.pilot_reference is None
    assert result.action.evidence_ids == (
        result.action_evidence.evidence_id,
        result.riec.evidence_item.evidence_id,
        result.protocol_evidence.evidence_id,
    )

    schemas = load_schema_registry()
    Draft202012Validator(
        schemas.lookup("protocol_result").validation_schema(),
        format_checker=FormatChecker(),
    ).validate(result.protocols.to_canonical_dict())
    Draft202012Validator(
        schemas.lookup("action_decision").validation_schema(),
        format_checker=FormatChecker(),
    ).validate(result.action.to_canonical_dict())
    assert ActionDecision.model_validate(result.action.to_canonical_dict()) == result.action

    serialized = json.dumps(
        {
            "protocols": result.protocols.to_canonical_dict(),
            "action": result.action.to_canonical_dict(),
            "protocol_evidence": result.protocol_evidence.to_canonical_dict(),
            "action_evidence": result.action_evidence.to_canonical_dict(),
        },
        sort_keys=True,
    )
    assert str(tmp_path) not in serialized
    assert run.run_id not in serialized
    assert source.source_id not in serialized
    assert "product_A" not in serialized
    assert "batch_01" not in serialized

    ledger = builder.finalize()
    assert len(ledger.items) == 3


def test_fill_service_rejects_nonfrozen_contract_evidence_profile_before_append(
    tmp_path: Path,
) -> None:
    normalized = (FIXTURE_ROOT / "normalized.csv").read_bytes()
    repository = SourceRepository(RuntimeSettings(ephemeral_root=tmp_path / "runtime"))
    run = repository.create_run()
    source = repository.register_built_in(
        run.run_id,
        built_in_key="macro02_profile_mismatch",
        display_name="Macro 02 public synthetic",
        payload=normalized,
    )
    profile = profile_dataset(repository, run_id=run.run_id, source_id=source.source_id)
    assert isinstance(profile, DatasetProfile)
    payload = json.loads((FIXTURE_ROOT / "confirmed_contract.json").read_text(encoding="utf-8"))
    payload["evidence_profile"]["min_rows"] = 79
    contract = AuditContract.model_validate(payload)
    builder = EvidenceLedgerBuilder(f"RUN-{run.run_id[4:16].upper()}")

    result = AuditService().run_audit(
        repository,
        run_id=run.run_id,
        source_id=source.source_id,
        contract=contract,
        dataset_profile=profile,
        registry_snapshot=load_run_registry_snapshot(),
        evidence_builder=builder,
    )

    assert not isinstance(result, FillProtocolActionResult)
    assert result.code == "FILL_EVIDENCE_PROFILE_MISMATCH"
    assert result.safe_details == {}
    assert builder.items == ()


def test_fill_service_pilot_path_and_aggregate_evidence_are_deterministic(
    tmp_path: Path,
) -> None:
    normalized = (FIXTURE_ROOT / "normalized.csv").read_bytes().replace(b"product_B", b"product_A")
    repository = SourceRepository(RuntimeSettings(ephemeral_root=tmp_path / "runtime"))
    run = repository.create_run()
    source = repository.register_built_in(
        run.run_id,
        built_in_key="macro02_pilot_path",
        display_name="Macro 02 public pilot fixture",
        payload=normalized,
    )
    profile = profile_dataset(repository, run_id=run.run_id, source_id=source.source_id)
    assert isinstance(profile, DatasetProfile)
    contract_payload = json.loads(
        (FIXTURE_ROOT / "confirmed_contract.json").read_text(encoding="utf-8")
    )
    contract_payload["source"]["dataset_id"] = profile.dataset_id
    contract_payload["source"]["dataset_sha256"] = profile.dataset_sha256
    contract_payload["policy"]["alpha"] = 0.1
    contract = canonicalize_audit_contract(AuditContract.model_validate(contract_payload))
    artifact_run_id = f"RUN-{run.run_id[4:16].upper()}"
    registry = load_run_registry_snapshot()

    builder = EvidenceLedgerBuilder(artifact_run_id)
    result = AuditService().run_audit(
        repository,
        run_id=run.run_id,
        source_id=source.source_id,
        contract=contract,
        dataset_profile=profile,
        registry_snapshot=registry,
        evidence_builder=builder,
    )
    assert isinstance(result, FillProtocolActionResult), getattr(result, "code", None)
    assert len(builder.items) == 3
    assert result.action.state is ActionState.PILOT_ONLY_CONSERVATIVE
    assert result.action.safe_headroom.basis is HeadroomBasis.BOOTSTRAP_LOWER_BOUNDS
    assert result.action.pilot_reference is not None
    assert result.action.pilot_reference.lower > 0.0
    assert result.action.pilot_reference.upper >= result.action.pilot_reference.lower

    protocol_payload = result.protocols.to_canonical_dict()
    protocol_payload["run_id"] = "RUN-000000000000"
    action_payload = result.action.to_canonical_dict()
    action_payload["run_id"] = "RUN-000000000000"
    assert canonical_sha256(protocol_payload) == (
        "8e6ca99962a236142c812b7c06b0b1c90072154b4f5673adb2af467ca6909212"
    )
    assert canonical_sha256(action_payload) == (
        "d0f73f35e5a78760ef20fa9df257b0ef5c8b8e84bab42c580a44ef9ee48c1970"
    )
    assert result.protocol_evidence.evidence_id == "EV-PROTOCOL-4222F6C482B4"
    assert result.protocol_evidence.content_sha256 == (
        "4222f6c482b434779c7e887466ca4e6f97411bda3d6ccd320a20293799bb54bb"
    )
    assert result.action_evidence.evidence_id == "EV-ACTION-AB2A45B4F294"
    assert result.action_evidence.content_sha256 == (
        "ab2a45b4f29448aededc5b6631f4d90b27c35838e75f00efe67600cadfaabba0"
    )
