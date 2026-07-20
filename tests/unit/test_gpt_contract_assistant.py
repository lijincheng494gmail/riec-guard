from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace

import pytest

from riec_guard.contract.models import DatasetProfile
from riec_guard.errors import ErrorEnvelope
from riec_guard.gpt.client import FixtureStructuredGptClient, OpenAIResponsesClient
from riec_guard.gpt.contract_assistant import suggest_contract_mapping
from riec_guard.gpt.models import (
    CONTRACT_PROMPT_VERSION,
    ContractRole,
    ContractSuggestion,
    ContractSuggestionBody,
    GptCallStatus,
    GptTask,
    OutputT,
    StructuredGptResponse,
)
from riec_guard.gpt.workflow import build_fixture_gpt_client

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_PROFILE_FIXTURE = (
    _REPOSITORY_ROOT / "tests" / "golden" / "fixtures" / "stage1" / "dataset_profile.json"
)


def _profile() -> DatasetProfile:
    return DatasetProfile.model_validate(json.loads(_PROFILE_FIXTURE.read_text(encoding="utf-8")))


def _suggestion_body(*, deployment_group: str = "batch_id") -> ContractSuggestionBody:
    columns = {
        ContractRole.QUANTITY: "quantity",
        ContractRole.PRODUCT: "product",
        ContractRole.DEPLOYMENT_GROUP: deployment_group,
        ContractRole.TIME: "timestamp",
        ContractRole.STREAM: "stream",
        ContractRole.SHIFT: "shift",
    }
    return ContractSuggestionBody.model_validate(
        {
            "role_suggestions": tuple(
                {
                    "role": role,
                    "column": columns[role],
                    "confidence": 0.8,
                    "reason": "Matches a supplied safe-profile semantic hint.",
                }
                for role in ContractRole
            ),
            "likely_measurement_unit": None,
            "unit_evidence": None,
            "missing_required_inputs": (),
            "clarification_questions": ("Confirm every proposed mapping.",),
            "requires_human_confirmation": True,
            "analysis_permitted": False,
        }
    )


def test_valid_contract_suggestion_is_advisory_and_profile_bound() -> None:
    profile = _profile()
    result = suggest_contract_mapping(
        dataset_profile=profile,
        client=build_fixture_gpt_client(),
    )

    assert isinstance(result, ContractSuggestion)
    valid_columns = {column.name for column in profile.column_profiles}
    assert {item.column for item in result.role_suggestions} <= valid_columns
    assert all(0 <= item.confidence <= 1 and item.reason for item in result.role_suggestions)
    assert result.requires_human_confirmation
    assert not result.analysis_permitted
    assert result.likely_measurement_unit is None
    assert result.unit_evidence is None
    assert not hasattr(result, "nominal_quantity")
    assert not hasattr(result, "lower_limit")
    assert not hasattr(result, "alpha")


def test_unknown_or_invented_deployment_group_is_rejected() -> None:
    client = FixtureStructuredGptClient(
        {GptTask.CONTRACT_ASSISTANT: _suggestion_body(deployment_group="invented_group")}
    )

    result = suggest_contract_mapping(dataset_profile=_profile(), client=client)

    assert isinstance(result, ErrorEnvelope)
    assert result.code == "GPT_CONTRACT_SUGGESTION_INVALID"
    assert result.error_class.value == "api_invalid_output"
    assert "AuditContract" not in result.to_canonical_json()


def test_openai_adapter_uses_fixed_bounded_responses_parse_shape() -> None:
    calls: list[dict[str, object]] = []
    factory_calls: list[dict[str, object]] = []
    body = _suggestion_body()

    class FakeResponses:
        def parse(self, **kwargs: object) -> object:
            calls.append(kwargs)
            return SimpleNamespace(
                id="resp_test_contract",
                model="gpt-5.6",
                status="completed",
                output=(),
                output_parsed=body,
                usage=SimpleNamespace(input_tokens=10, output_tokens=20, total_tokens=30),
            )

    def factory(**kwargs: object) -> object:
        factory_calls.append(kwargs)
        return SimpleNamespace(responses=FakeResponses())

    client = OpenAIResponsesClient(client_factory=factory)
    result = client.generate(
        task=GptTask.CONTRACT_ASSISTANT,
        prompt_version=CONTRACT_PROMPT_VERSION,
        payload={"dataset_profile": {"columns": ("quantity", "batch_id")}},
        output_model=ContractSuggestionBody,
    )

    assert result.metadata.status is GptCallStatus.SUCCESS
    assert len(factory_calls) == 1 and factory_calls[0]["max_retries"] == 0
    assert len(calls) == 1
    call = calls[0]
    assert call["model"] == "gpt-5.6"
    assert call["store"] is False
    assert call["text_format"] is ContractSuggestionBody
    assert call["tools"] == []
    assert call["parallel_tool_calls"] is False
    assert call["stream"] is False
    assert isinstance(call["max_output_tokens"], int)
    assert 0 < call["max_output_tokens"] <= 2_000
    assert "raw_rows" not in str(call["input"])


def test_openai_adapter_rejects_arbitrary_model_and_prompt_version() -> None:
    with pytest.raises(ValueError, match="fixed"):
        OpenAIResponsesClient(model="arbitrary-model")
    client = FixtureStructuredGptClient({GptTask.CONTRACT_ASSISTANT: _suggestion_body()})
    with pytest.raises(ValueError, match="prompt version"):
        client.generate(
            task=GptTask.CONTRACT_ASSISTANT,
            prompt_version="decision-memo.v1",
            payload={"profile": {}},
            output_model=ContractSuggestionBody,
        )


def test_contract_service_rejects_unbound_transport_metadata() -> None:
    delegate = build_fixture_gpt_client()

    class TamperedClient:
        def generate(
            self,
            *,
            task: GptTask,
            prompt_version: str,
            payload: Mapping[str, object],
            output_model: type[OutputT],
        ) -> StructuredGptResponse[OutputT]:
            response = delegate.generate(
                task=task,
                prompt_version=prompt_version,
                payload=payload,
                output_model=output_model,
            )
            metadata = response.metadata.model_copy(update={"sanitized_input_sha256": "0" * 64})
            return StructuredGptResponse(
                output=response.output,
                request=response.request,
                metadata=metadata,
            )

    result = suggest_contract_mapping(dataset_profile=_profile(), client=TamperedClient())

    assert isinstance(result, ErrorEnvelope)
    assert result.code == "GPT_CONTRACT_RESPONSE_UNBOUND"
    assert result.error_class.value == "security_block"
