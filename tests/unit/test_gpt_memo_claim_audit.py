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
from riec_guard.gpt.claim_auditor import audit_memo_claims
from riec_guard.gpt.client import FixtureStructuredGptClient
from riec_guard.gpt.memo import build_recorded_evidence_context, draft_decision_memo
from riec_guard.gpt.models import (
    MEMO_PROMPT_VERSION,
    ClaimAuditResult,
    ClaimAuditStatus,
    ClaimVerdict,
    DecisionMemo,
    DecisionMemoBody,
    EvidenceContext,
    FixtureFailureMode,
    GptCallStatus,
    GptTask,
)
from riec_guard.gpt.sanitizer import payload_sha256
from riec_guard.gpt.workflow import build_fixture_gpt_client
from riec_guard.settings import RuntimeSettings

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_SCENARIOS = (
    "stable_symmetric",
    "heavy_tail_particulate",
    "batch_drift_change_point",
)


@pytest.fixture(scope="module")
def contexts(tmp_path_factory: pytest.TempPathFactory) -> dict[str, EvidenceContext]:
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
    result: dict[str, EvidenceContext] = {}
    for scenario_id in _SCENARIOS:
        generated = generate_scenario(scenario_id)
        root = tmp_path_factory.mktemp(f"gpt-memo-{scenario_id}")
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
        result[scenario_id] = build_recorded_evidence_context(
            dataset_profile=profile,
            catalog=catalog,
            benchmark_summary=summary,
            scenario_id=scenario_id,
        )
    return result


@pytest.mark.parametrize(
    ("scenario_id", "state", "interval"),
    (
        ("stable_symmetric", ActionState.PILOT_RANGE_SUPPORTED, "0.15–0.40 mL"),
        ("heavy_tail_particulate", ActionState.PILOT_ONLY_CONSERVATIVE, "0.05–0.14 mL"),
        ("batch_drift_change_point", ActionState.DIAGNOSE_PROCESS_FIRST, None),
    ),
)
def test_recorded_scenario_memos_preserve_action_semantics_and_citations(
    contexts: dict[str, EvidenceContext],
    scenario_id: str,
    state: ActionState,
    interval: str | None,
) -> None:
    context = contexts[scenario_id]
    result = draft_decision_memo(
        evidence_context=context,
        client=build_fixture_gpt_client(),
    )

    assert isinstance(result, DecisionMemo)
    assert result.action_state is state
    text = " ".join(
        (
            result.decision_snapshot,
            result.what_the_evidence_shows,
            result.why_protocol_choice_matters,
            result.recommended_next_step,
        )
    )
    if interval is not None:
        assert interval in text
        assert "controlled pilot" in text
        assert "not a production setpoint" in text
    else:
        assert "no pilot interval" in text
        assert "process diagnosis" in text
        assert "mL" not in text
    if state is ActionState.PILOT_ONLY_CONSERVATIVE:
        assert "Protocol disagreement" in text
        assert "conservative" in text
        assert "full agreement" not in text
    if state is ActionState.DIAGNOSE_PROCESS_FIRST:
        assert "Process instability" in text
    valid_facts = {fact.fact_key for fact in context.facts}
    for finding in result.findings:
        assert set(finding.evidence_ids) <= set(context.valid_evidence_ids)
        assert set(finding.fact_keys) <= valid_facts
    assert set(result.limitations) == set(context.limitations)
    assert "is compliant" not in text.casefold()


def test_numeric_hallucination_is_rejected_before_claim_audit(
    contexts: dict[str, EvidenceContext],
) -> None:
    context = contexts["stable_symmetric"]
    body = _fixture_memo_body(context)
    bad = body.model_copy(update={"what_the_evidence_shows": "This will save 12% annually."})
    client = FixtureStructuredGptClient({GptTask.DECISION_MEMO: bad})

    result = draft_decision_memo(evidence_context=context, client=client)

    assert isinstance(result, ErrorEnvelope)
    assert result.code == "GPT_MEMO_SEMANTIC_REJECTED"


def test_unknown_evidence_is_rejected_by_memo_validation(
    contexts: dict[str, EvidenceContext],
) -> None:
    context = contexts["stable_symmetric"]
    body = _fixture_memo_body(context)
    fabricated = "EV-ACTION-AAAAAAAAAAAA"
    finding = body.findings[0].model_copy(update={"evidence_ids": (fabricated,)})
    bad = body.model_copy(update={"findings": (finding, *body.findings[1:])})
    client = FixtureStructuredGptClient({GptTask.DECISION_MEMO: bad})

    result = draft_decision_memo(evidence_context=context, client=client)

    assert isinstance(result, ErrorEnvelope)
    assert result.code == "GPT_MEMO_SEMANTIC_REJECTED"


@pytest.mark.parametrize(
    "claim",
    (
        "The recorded scenario achieved savings.",
        "The process is compliant.",
        "The change provides guaranteed safety.",
        "Use this optimal production setpoint.",
        "The method is universally validated.",
    ),
)
def test_prohibited_claims_block_and_deterministic_precedence_wins(
    contexts: dict[str, EvidenceContext],
    claim: str,
) -> None:
    context = contexts["stable_symmetric"]
    memo = _valid_memo(context)
    modified = _replace_memo_section(memo, what_the_evidence_shows=claim)

    result = audit_memo_claims(
        memo=modified,
        evidence_context=context,
        client=build_fixture_gpt_client(),
    )

    assert isinstance(result, ClaimAuditResult)
    assert result.status is ClaimAuditStatus.BLOCKED
    assert any(review.verdict is ClaimVerdict.PROHIBITED for review in result.deterministic_reviews)
    assert all(review.verdict is ClaimVerdict.SUPPORTED for review in result.model_reviews)
    assert any(review.verdict is ClaimVerdict.PROHIBITED for review in result.reviews)


def test_cautious_retrospective_synthetic_claim_passes(
    contexts: dict[str, EvidenceContext],
) -> None:
    context = contexts["stable_symmetric"]
    memo = _valid_memo(context)
    cautious = (
        "The recorded synthetic scenario supports a retrospective screening range for a "
        "controlled pilot, subject to engineering review."
    )
    modified = _replace_memo_section(memo, what_the_evidence_shows=cautious)

    result = audit_memo_claims(
        memo=modified,
        evidence_context=context,
        client=build_fixture_gpt_client(),
    )

    assert isinstance(result, ClaimAuditResult)
    assert result.status is ClaimAuditStatus.PASS
    assert all(
        review.verdict in {ClaimVerdict.SUPPORTED, ClaimVerdict.NOT_A_CLAIM}
        for review in result.reviews
    )


def test_claim_audit_blocks_fabricated_evidence_even_when_model_supports(
    contexts: dict[str, EvidenceContext],
) -> None:
    context = contexts["stable_symmetric"]
    memo = _valid_memo(context)
    finding = memo.findings[0].model_copy(update={"evidence_ids": ("EV-ACTION-BBBBBBBBBBBB",)})
    modified = _replace_memo_section(memo, findings=(finding, *memo.findings[1:]))

    result = audit_memo_claims(
        memo=modified,
        evidence_context=context,
        client=build_fixture_gpt_client(),
    )

    assert isinstance(result, ClaimAuditResult)
    assert result.status is ClaimAuditStatus.BLOCKED
    assert result.deterministic_validation_status == "blocked"


def test_claim_model_malformed_output_is_explicitly_blocked(
    contexts: dict[str, EvidenceContext],
) -> None:
    context = contexts["stable_symmetric"]
    memo = _valid_memo(context)
    client = FixtureStructuredGptClient(
        {},
        failure_modes={GptTask.CLAIM_AUDITOR: FixtureFailureMode.MALFORMED},
    )

    result = audit_memo_claims(memo=memo, evidence_context=context, client=client)

    assert isinstance(result, ClaimAuditResult)
    assert result.status is ClaimAuditStatus.BLOCKED
    assert result.response.status is GptCallStatus.ERROR
    assert result.failure_reason is not None


def test_direct_claim_audit_blocks_forged_action_semantics(
    contexts: dict[str, EvidenceContext],
) -> None:
    context = contexts["batch_drift_change_point"]
    memo = _valid_memo(context)
    forged = _replace_memo_section(
        memo,
        decision_snapshot="The current evidence supports an operational trial.",
        what_the_evidence_shows="The process can move directly to a trial.",
        why_protocol_choice_matters="The available evidence is adequate for that trial.",
        recommended_next_step="Proceed with a controlled trial based on the current evidence.",
    )

    result = audit_memo_claims(
        memo=forged,
        evidence_context=context,
        client=build_fixture_gpt_client(),
    )

    assert isinstance(result, ClaimAuditResult)
    assert result.status is ClaimAuditStatus.BLOCKED
    assert result.deterministic_validation_status == "blocked"


def _fixture_memo_body(context: EvidenceContext) -> DecisionMemoBody:
    result = build_fixture_gpt_client().generate(
        task=GptTask.DECISION_MEMO,
        prompt_version=MEMO_PROMPT_VERSION,
        payload={"evidence_context": context.to_canonical_dict()},
        output_model=DecisionMemoBody,
    )
    assert result.output is not None
    return result.output


def _valid_memo(context: EvidenceContext) -> DecisionMemo:
    result = draft_decision_memo(evidence_context=context, client=build_fixture_gpt_client())
    assert isinstance(result, DecisionMemo)
    return result


def _replace_memo_section(memo: DecisionMemo, **updates: object) -> DecisionMemo:
    body_payload = {
        "title": updates.get("title", memo.title),
        "decision_snapshot": updates.get("decision_snapshot", memo.decision_snapshot),
        "what_the_evidence_shows": updates.get(
            "what_the_evidence_shows", memo.what_the_evidence_shows
        ),
        "why_protocol_choice_matters": updates.get(
            "why_protocol_choice_matters", memo.why_protocol_choice_matters
        ),
        "recommended_next_step": updates.get("recommended_next_step", memo.recommended_next_step),
        "limitations": updates.get("limitations", memo.limitations),
        "findings": updates.get("findings", memo.findings),
    }
    body = DecisionMemoBody.model_validate(body_payload)
    response = memo.response.model_copy(
        update={"normalized_output_sha256": payload_sha256(body.to_canonical_dict())}
    )
    return memo.model_copy(update={**updates, "response": response})
