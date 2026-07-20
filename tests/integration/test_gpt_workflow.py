from __future__ import annotations

from pathlib import Path

import pytest

from riec_guard.benchmarks.catalog import parse_json_object, validate_benchmark_identity
from riec_guard.benchmarks.models import DemoBenchmarkSummary, ScenarioCatalog
from riec_guard.benchmarks.scenarios import generate_scenario
from riec_guard.contract.models import ActionState, DatasetProfile
from riec_guard.contract.profiler import profile_dataset
from riec_guard.domain.source import SourceRepository
from riec_guard.errors import ErrorEnvelope
from riec_guard.gpt.client import FixtureStructuredGptClient
from riec_guard.gpt.memo import build_recorded_evidence_context
from riec_guard.gpt.models import (
    FixtureFailureMode,
    EvidenceContext,
    GptExecutionMode,
    GptTask,
    GptWorkflowResult,
    GptWorkflowStatus,
)
from riec_guard.gpt.sanitizer import payload_sha256
from riec_guard.gpt.workflow import (
    build_fixture_gpt_client,
    run_gpt_interpretation_workflow,
)
from riec_guard.settings import RuntimeSettings

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_EXPECTED = {
    "stable_symmetric": ActionState.PILOT_RANGE_SUPPORTED,
    "heavy_tail_particulate": ActionState.PILOT_ONLY_CONSERVATIVE,
    "batch_drift_change_point": ActionState.DIAGNOSE_PROCESS_FIRST,
}


@pytest.fixture(scope="module")
def scenario_inputs(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, tuple[DatasetProfile, EvidenceContext]]:
    catalog = ScenarioCatalog.model_validate(
        parse_json_object(
            (_REPOSITORY_ROOT / "demo_assets" / "scenario_catalog.v1.json").read_bytes()
        )
    )
    summary = DemoBenchmarkSummary.model_validate(
        parse_json_object(
            (_REPOSITORY_ROOT / "demo_assets" / "benchmark_summary.v1.json").read_bytes()
        )
    )
    validate_benchmark_identity(summary, catalog=catalog)
    result: dict[str, tuple[DatasetProfile, EvidenceContext]] = {}
    for scenario_id in _EXPECTED:
        generated = generate_scenario(scenario_id)
        root = tmp_path_factory.mktemp(f"gpt-workflow-{scenario_id}")
        repository = SourceRepository(RuntimeSettings(ephemeral_root=root / "runs"))
        run = repository.create_run()
        source = repository.register_built_in(
            run.run_id,
            built_in_key=scenario_id,
            display_name=generated.definition.display_name,
            payload=generated.csv_bytes,
        )
        profile = profile_dataset(repository, run_id=run.run_id, source_id=source.source_id)
        repository.delete_run(run.run_id)
        assert isinstance(profile, DatasetProfile)
        context = build_recorded_evidence_context(
            dataset_profile=profile,
            catalog=catalog,
            benchmark_summary=summary,
            scenario_id=scenario_id,
        )
        result[scenario_id] = (profile, context)
    return result


@pytest.mark.parametrize(("scenario_id", "expected_state"), tuple(_EXPECTED.items()))
def test_fixture_workflow_integrates_all_recorded_scenarios_without_network(
    scenario_inputs: dict[str, tuple[DatasetProfile, EvidenceContext]],
    scenario_id: str,
    expected_state: ActionState,
) -> None:
    profile, context = scenario_inputs[scenario_id]
    client = build_fixture_gpt_client()

    result = run_gpt_interpretation_workflow(
        dataset_profile=profile,
        evidence_context=context,
        client=client,
    )

    assert isinstance(result, GptWorkflowResult)
    assert result.status is GptWorkflowStatus.COMPLETED
    assert result.fixture_non_live
    assert result.deterministic_analysis_available
    assert result.decision_memo is not None
    assert result.decision_memo.action_state is expected_state
    assert result.claim_audit is not None and result.claim_audit.status.value == "pass"
    assert len(result.audit_trail) == 3
    assert all(item.execution_mode is GptExecutionMode.FIXTURE for item in result.audit_trail)
    assert all(item.normalized_output_sha256 is not None for item in result.audit_trail)
    assert len(client.requests) == 3
    payload = result.to_canonical_dict()
    identity = payload.pop("normalized_output_sha256")
    assert identity == payload_sha256(payload)


@pytest.mark.parametrize(
    "failure_mode",
    (
        FixtureFailureMode.REFUSAL,
        FixtureFailureMode.INCOMPLETE,
        FixtureFailureMode.MALFORMED,
        FixtureFailureMode.TIMEOUT,
        FixtureFailureMode.AUTHENTICATION,
        FixtureFailureMode.ACCESS,
    ),
)
def test_fixture_failures_preserve_deterministic_analysis_availability(
    scenario_inputs: dict[str, tuple[DatasetProfile, EvidenceContext]],
    failure_mode: FixtureFailureMode,
) -> None:
    profile, context = scenario_inputs["stable_symmetric"]
    client = FixtureStructuredGptClient(
        {},
        failure_modes={GptTask.CONTRACT_ASSISTANT: failure_mode},
    )

    result = run_gpt_interpretation_workflow(
        dataset_profile=profile,
        evidence_context=context,
        client=client,
    )

    assert isinstance(result, GptWorkflowResult)
    assert result.status is GptWorkflowStatus.NARRATIVE_UNAVAILABLE
    assert result.fixture_non_live
    assert result.deterministic_analysis_available
    assert result.contract_suggestion is None
    assert result.decision_memo is None
    assert result.claim_audit is None
    assert result.failure_stage is GptTask.CONTRACT_ASSISTANT
    assert len(client.requests) == 1
    assert client.requests[0].execution_mode is GptExecutionMode.FIXTURE
    assert len(result.audit_trail) == 1
    assert result.audit_trail[0].execution_mode is GptExecutionMode.FIXTURE
    assert result.audit_trail[0].status.value != "success"


def test_workflow_rejects_tampered_context_with_safe_error(
    scenario_inputs: dict[str, tuple[DatasetProfile, EvidenceContext]],
) -> None:
    profile, context = scenario_inputs["stable_symmetric"]
    tampered = context.model_copy(update={"payload_sha256": "0" * 64})

    result = run_gpt_interpretation_workflow(
        dataset_profile=profile,
        evidence_context=tampered,
        client=build_fixture_gpt_client(),
    )

    assert isinstance(result, ErrorEnvelope)
    assert result.code == "GPT_WORKFLOW_CONTEXT_INVALID"
    assert result.error_class.value == "security_block"


def test_workflow_rejects_mixed_profile_and_context_provenance(
    scenario_inputs: dict[str, tuple[DatasetProfile, EvidenceContext]],
) -> None:
    profile, _ = scenario_inputs["stable_symmetric"]
    _, other_context = scenario_inputs["heavy_tail_particulate"]

    result = run_gpt_interpretation_workflow(
        dataset_profile=profile,
        evidence_context=other_context,
        client=build_fixture_gpt_client(),
    )

    assert isinstance(result, ErrorEnvelope)
    assert result.code == "GPT_WORKFLOW_CONTEXT_INVALID"
