#!/usr/bin/env python3
"""Explicit public-scenario smoke runner for the bounded GPT workflow."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from riec_guard.benchmarks.catalog import (
    json_asset_bytes,
    parse_json_object,
    validate_benchmark_identity,
)
from riec_guard.benchmarks.models import DemoBenchmarkSummary, ScenarioCatalog, ScenarioId
from riec_guard.benchmarks.scenarios import generate_scenario
from riec_guard.contract.models import DatasetProfile
from riec_guard.contract.profiler import profile_dataset
from riec_guard.domain.source import SourceRepository
from riec_guard.errors import ErrorEnvelope
from riec_guard.gpt.client import OpenAIResponsesClient
from riec_guard.gpt.memo import build_recorded_evidence_context
from riec_guard.gpt.models import GptWorkflowResult
from riec_guard.gpt.workflow import (
    build_fixture_gpt_client,
    run_gpt_interpretation_workflow,
)
from riec_guard.settings import RuntimeSettings

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_SCENARIO_CHOICES = tuple(item.value for item in ScenarioId)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=_SCENARIO_CHOICES, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--fixture", action="store_true", help="deterministic non-live mode")
    mode.add_argument("--live", action="store_true", help="explicit bounded OpenAI API mode")
    args = parser.parse_args()
    if args.live and not os.environ.get("OPENAI_API_KEY"):
        parser.error("--live requires OPENAI_API_KEY through the official SDK environment path")

    try:
        catalog, benchmark = _load_recorded_assets()
        profile = _profile_public_scenario(args.scenario)
        context = build_recorded_evidence_context(
            dataset_profile=profile,
            catalog=catalog,
            benchmark_summary=benchmark,
            scenario_id=args.scenario,
        )
        client = OpenAIResponsesClient() if args.live else build_fixture_gpt_client()
        result = run_gpt_interpretation_workflow(
            dataset_profile=profile,
            evidence_context=context,
            client=client,
        )
    except (OSError, TypeError, ValueError):
        print(json.dumps({"status": "error", "message": "The smoke run failed safely."}))
        return 2
    if isinstance(result, ErrorEnvelope):
        print(json.dumps(result.to_canonical_dict(), ensure_ascii=False, sort_keys=True))
        return 2
    print(json.dumps(_compact_summary(result), ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result.status.value == "completed" else 1


def _load_recorded_assets() -> tuple[ScenarioCatalog, DemoBenchmarkSummary]:
    catalog_bytes = (_REPOSITORY_ROOT / "demo_assets" / "scenario_catalog.v1.json").read_bytes()
    summary_bytes = (_REPOSITORY_ROOT / "demo_assets" / "benchmark_summary.v1.json").read_bytes()
    catalog = ScenarioCatalog.model_validate(parse_json_object(catalog_bytes))
    summary = DemoBenchmarkSummary.model_validate(parse_json_object(summary_bytes))
    validate_benchmark_identity(summary, catalog=catalog)
    if catalog_bytes != json_asset_bytes(catalog) or summary_bytes != json_asset_bytes(summary):
        raise ValueError("recorded public assets are not byte canonical")
    return catalog, summary


def _profile_public_scenario(scenario_id: str) -> DatasetProfile:
    generated = generate_scenario(scenario_id)
    with tempfile.TemporaryDirectory(prefix="riec-guard-gpt-smoke-") as temporary:
        repository = SourceRepository(
            RuntimeSettings(ephemeral_root=Path(temporary) / "ephemeral-runs")
        )
        roots = repository.create_run()
        try:
            source = repository.register_built_in(
                roots.run_id,
                built_in_key=generated.definition.scenario_id.value,
                display_name=generated.definition.display_name,
                payload=generated.csv_bytes,
            )
            profile = profile_dataset(
                repository,
                run_id=roots.run_id,
                source_id=source.source_id,
            )
        finally:
            repository.delete_run(roots.run_id)
    if not isinstance(profile, DatasetProfile):
        raise ValueError("public scenario profiling failed")
    return profile


def _compact_summary(result: GptWorkflowResult) -> dict[str, object]:
    memo = result.decision_memo
    audit = result.claim_audit
    return {
        "status": result.status.value,
        "fixture_non_live": result.fixture_non_live,
        "deterministic_analysis_available": result.deterministic_analysis_available,
        "requested_model": result.requested_model,
        "prompt_versions": result.prompt_versions,
        "action_state": memo.action_state.value if memo is not None else None,
        "memo": (
            {
                "title": memo.title,
                "decision_snapshot": memo.decision_snapshot,
                "what_the_evidence_shows": memo.what_the_evidence_shows,
                "why_protocol_choice_matters": memo.why_protocol_choice_matters,
                "recommended_next_step": memo.recommended_next_step,
                "limitations": memo.limitations,
            }
            if memo is not None
            else None
        ),
        "claim_audit": (
            {
                "status": audit.status.value,
                "deterministic_validation_status": audit.deterministic_validation_status,
                "verdicts": tuple(review.verdict.value for review in audit.reviews),
            }
            if audit is not None
            else None
        ),
        "calls": tuple(
            {
                "task": metadata.task.value,
                "status": metadata.status.value,
                "response_id": metadata.response_id,
                "returned_model": metadata.returned_model,
                "usage": metadata.usage.to_canonical_dict(),
            }
            for metadata in result.audit_trail
        ),
        "referenced_evidence_ids": result.referenced_evidence_ids,
        "workflow_sha256": result.normalized_output_sha256,
        "message": result.user_message,
    }


if __name__ == "__main__":
    raise SystemExit(main())
