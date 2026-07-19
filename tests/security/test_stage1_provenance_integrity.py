from __future__ import annotations

import json
from pathlib import Path

import pytest

from riec_guard.evidence.ids import EvidenceError, EvidenceErrorCode
from riec_guard.evidence.ledger import EvidenceLedgerBuilder, bind_ledger_items
from riec_guard.evidence.models import EvidenceLedger
from riec_guard.riec.registry import load_run_registry_snapshot
from riec_guard.telemetry.manifest import ManifestError, ManifestErrorCode, RunManifestBuilder
from riec_guard.telemetry.models import ManifestRegistries, RunStatus

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_EXAMPLE = REPOSITORY_ROOT / "schemas/examples/evidence_ledger.example.json"
RUN_ID = "RUN-ABCDEF123456"
STARTED_AT = "2026-07-19T00:00:00Z"
FINISHED_AT = "2026-07-19T00:01:00Z"
FROZEN_LEDGER_HASH = "b533abc49c9438e59ed493e94b6c855b41bd8e87ab7e0646411d951dc06c9ca7"


def _prepared_builder(tmp_path: Path) -> RunManifestBuilder:
    artifact_root = tmp_path / RUN_ID / "artifacts"
    artifact_root.mkdir(parents=True)
    (artifact_root / "result.json").write_text("{}", encoding="utf-8")
    builder = RunManifestBuilder(
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
            "dependency_lock_sha256": "1" * 64,
        },
        contract={
            "contract_id": "AC-ABCDEF123456",
            "sha256": "2" * 64,
            "schema_version": "1.0.0",
            "confirmation_status": "confirmed",
        },
        registry_snapshot=load_run_registry_snapshot(),
        action_engine_version="1.0.0",
        randomness={
            "global_seed": 20260718,
            "bootstrap_seed": 20260718,
            "bootstrap_replicates": 200,
        },
        configured_model="gpt-5.6-sol",
        artifact_root=artifact_root,
        storage_root_class="public_ephemeral",
    )
    builder.register_input(
        artifact_id="fixture.v1",
        sha256="3" * 64,
        classification="public_synthetic",
        row_count=3,
    )
    builder.register_artifact(
        artifact_id="result.json",
        relative_path="result.json",
        media_type="application/json",
        public_safe=True,
    )
    return builder


def test_r02_false_candidate_hash_cannot_finalize_against_snapshot(tmp_path: Path) -> None:
    builder = _prepared_builder(tmp_path)
    payload = builder._registries.to_canonical_dict()
    payload["candidate_registry"]["sha256"] = "0" * 64  # type: ignore[index]
    builder._registries = ManifestRegistries.model_validate(payload)
    builder.start().complete(finished_at=FINISHED_AT)
    with pytest.raises(ManifestError) as caught:
        builder.finalize()
    assert caught.value.code is ManifestErrorCode.MANIFEST_REGISTRY_INVALID
    assert "0" * 64 not in str(caught.value)
    assert str(REPOSITORY_ROOT) not in str(caught.value)


def test_r02_frozen_evidence_cannot_be_imported_into_another_run() -> None:
    source = EvidenceLedger.model_validate(json.loads(EVIDENCE_EXAMPLE.read_text(encoding="utf-8")))
    assert source.run_id == "RUN-F0DE9EA43245"
    target = EvidenceLedgerBuilder(RUN_ID)

    for naked_item in source.items:
        with pytest.raises(EvidenceError) as caught_naked:
            target.append(naked_item)
        assert caught_naked.value.code is EvidenceErrorCode.EVIDENCE_RUN_MISMATCH

    for foreign_record in bind_ledger_items(
        source,
        expected_source_run_id="RUN-F0DE9EA43245",
        expected_ledger_sha256=FROZEN_LEDGER_HASH,
    ):
        with pytest.raises(EvidenceError) as caught_bound:
            target.append(foreign_record)
        assert caught_bound.value.code is EvidenceErrorCode.EVIDENCE_RUN_MISMATCH

    assert len(source.items) == 11
    assert target.items == ()


def test_r02_direct_terminal_state_mutation_cannot_finalize(tmp_path: Path) -> None:
    builder = _prepared_builder(tmp_path)
    builder._status = RunStatus.COMPLETED
    builder._finished_at = FINISHED_AT
    with pytest.raises(ManifestError) as caught:
        builder.finalize()
    assert caught.value.code is ManifestErrorCode.MANIFEST_INVALID_TRANSITION
