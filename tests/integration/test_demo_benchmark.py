from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from riec_guard.benchmarks.models import DemoScenarioResult
from riec_guard.benchmarks.runner import run_public_demo_scenario
from riec_guard.contract.models import (
    ActionDecision,
    ActionState,
    OrderedStability,
    ProtocolId,
    ProtocolResult,
    ProtocolStatus,
    RiecSelection,
)
from riec_guard.contract.schema_loader import load_schema_registry
from riec_guard.domain.source import SourceRepository
from riec_guard.evidence.ids import verify_evidence_item
from riec_guard.evidence.ledger import verify_ledger
from riec_guard.evidence.models import EvidenceComponent, EvidenceLedger
from riec_guard.settings import RuntimeSettings

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_SCENARIO_IDS = (
    "stable_symmetric",
    "heavy_tail_particulate",
    "batch_drift_change_point",
)


def test_stable_public_demo_runs_once_through_production_defaults(tmp_path: Path) -> None:
    runtime_root = tmp_path / "runtime"
    repository = SourceRepository(RuntimeSettings(ephemeral_root=runtime_root))

    result = run_public_demo_scenario(repository, scenario_id="stable_symmetric")

    assert isinstance(result, DemoScenarioResult), getattr(result, "code", None)
    assert result.action.state is ActionState.PILOT_RANGE_SUPPORTED
    assert result.action.gates.ordered_stability is OrderedStability.PASS
    assert result.action.gates.evidence_sufficient
    assert not result.action.conflict.material_protocol_conflict
    assert result.action.pilot_reference is not None
    assert 0 < result.action.pilot_reference.lower <= result.action.pilot_reference.upper

    entries = {entry.protocol_id: entry for entry in result.protocols.results}
    assert tuple(entry.protocol_id for entry in result.protocols.results) == (
        ProtocolId.D0_MEAN_DIAGNOSTIC,
        ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE,
        ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL,
        ProtocolId.H3_STUDENT_T_RESIDUAL_TAIL,
        ProtocolId.U1_GROUP_BOOTSTRAP_BOUND,
        ProtocolId.G1_ORDERED_STABILITY_SCREEN,
        ProtocolId.G2_EVIDENCE_SUFFICIENCY_GATE,
    )
    u1 = entries[ProtocolId.U1_GROUP_BOOTSTRAP_BOUND]
    assert u1.status is ProtocolStatus.OK
    u1_metrics = {metric.name: metric.value for metric in u1.metrics}
    assert u1_metrics["requested_replicates"] == 200
    assert u1_metrics["successful_replicates"] == 200
    assert u1_metrics["failed_replicates"] == 0
    assert u1_metrics["bootstrap_seed"] == 20260718

    g2 = entries[ProtocolId.G2_EVIDENCE_SUFFICIENCY_GATE]
    assert g2.status is ProtocolStatus.OK
    g2_metrics = {metric.name: metric.value for metric in g2.metrics}
    assert g2_metrics["minimum_product_rows"] == 528
    assert g2_metrics["minimum_product_groups"] == 12
    assert g2_metrics["expected_tail_count"] == 5.28
    assert g2_metrics["action_supported"] is True

    selection_payload = result.selection.to_canonical_dict()
    protocol_payload = result.protocols.to_canonical_dict()
    action_payload = result.action.to_canonical_dict()
    ledger_payload = result.evidence_ledger.to_canonical_dict()
    assert RiecSelection.model_validate(selection_payload) == result.selection
    assert ProtocolResult.model_validate(protocol_payload) == result.protocols
    assert ActionDecision.model_validate(action_payload) == result.action
    assert EvidenceLedger.model_validate(ledger_payload) == result.evidence_ledger

    schemas = load_schema_registry()
    for logical_name, payload in (
        ("riec_selection", selection_payload),
        ("protocol_result", protocol_payload),
        ("action_decision", action_payload),
        ("evidence_ledger", ledger_payload),
    ):
        Draft202012Validator(
            schemas.lookup(logical_name).validation_schema(),
            format_checker=FormatChecker(),
        ).validate(payload)

    ledger = result.evidence_ledger
    assert tuple(item.component for item in ledger.items) == (
        EvidenceComponent.RIEC,
        EvidenceComponent.PROTOCOL,
        EvidenceComponent.ACTION,
    )
    for item in ledger.items:
        verify_evidence_item(item)
    verification = verify_ledger(ledger)
    assert verification.item_count == 3
    assert verification.graph.node_count == 3
    assert verification.graph.edge_count == 3
    riec, protocol, action = ledger.items
    assert protocol.parent_evidence_ids == (riec.evidence_id,)
    assert set(action.parent_evidence_ids) == {riec.evidence_id, protocol.evidence_id}
    assert set(verification.graph.ancestors(action.evidence_id)) == {
        riec.evidence_id,
        protocol.evidence_id,
    }

    assert result.summary.action_state is ActionState.PILOT_RANGE_SUPPORTED
    assert result.summary.g1_state.value == "pass"
    assert result.summary.g2.action_supported
    assert result.summary.u1.requested_replicates == 200
    assert result.summary.u1.successful_replicates == 200
    assert result.summary.u1.failed_replicates == 0
    assert result.summary.u1.seed == 20260718

    serialized = json.dumps(
        {
            "definition": result.definition.to_canonical_dict(),
            "selection": selection_payload,
            "protocols": protocol_payload,
            "action": action_payload,
            "evidence_ledger": ledger_payload,
            "summary": result.summary.to_canonical_dict(),
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    assert str(tmp_path) not in serialized
    assert "source_id" not in serialized
    assert "source_run_id" not in serialized
    assert "csv_bytes" not in serialized
    assert "raw_rows" not in serialized and "row_data" not in serialized
    assert "product_A" not in serialized and "batch_01" not in serialized
    assert re.search(r"RUN-[a-f0-9]{32}", serialized) is None
    assert re.search(r"/(?:Users|home|tmp|var/tmp)/", serialized) is None
    assert runtime_root.is_dir() and tuple(runtime_root.iterdir()) == ()


def test_production_analysis_has_no_benchmark_imports_or_scenario_branches() -> None:
    production_paths = (
        *(REPOSITORY_ROOT / "src" / "riec_guard" / "riec").glob("*.py"),
        *(REPOSITORY_ROOT / "src" / "riec_guard" / "protocols").glob("*.py"),
        *(REPOSITORY_ROOT / "src" / "riec_guard" / "decision").glob("*.py"),
        REPOSITORY_ROOT / "src" / "riec_guard" / "app_service.py",
    )
    assert production_paths

    for path in production_paths:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=path.name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(
                    not alias.name.startswith("riec_guard.benchmarks") for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("riec_guard.benchmarks")
        assert all(scenario_id not in source for scenario_id in _SCENARIO_IDS)
