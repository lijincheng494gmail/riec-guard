"""Advisory, profile-only contract mapping assistance."""

from __future__ import annotations

from riec_guard.contract.models import DatasetProfile
from riec_guard.errors import ErrorClass, ErrorEnvelope
from riec_guard.gpt.client import StructuredGptClient, structured_response_is_bound
from riec_guard.gpt.models import (
    ARTIFACT_VERSION,
    CONTRACT_PROMPT_VERSION,
    ContractRole,
    ContractSuggestion,
    ContractSuggestionBody,
    GptCallStatus,
    GptTask,
    gpt_error,
)
from riec_guard.gpt.sanitizer import GptPayloadBoundaryError, sanitize_dataset_profile

_ROLE_ORDER = (
    ContractRole.QUANTITY,
    ContractRole.PRODUCT,
    ContractRole.DEPLOYMENT_GROUP,
    ContractRole.TIME,
    ContractRole.STREAM,
    ContractRole.SHIFT,
)


def suggest_contract_mapping(
    *,
    dataset_profile: DatasetProfile,
    client: StructuredGptClient,
) -> ContractSuggestion | ErrorEnvelope:
    """Return a validated proposal; never create or confirm an AuditContract."""

    if not isinstance(dataset_profile, DatasetProfile):
        return gpt_error(
            "GPT_PROFILE_TYPE_INVALID",
            "Contract assistance requires a canonical dataset profile.",
            error_class=ErrorClass.VALIDATION,
            recoverable=True,
            user_action="Create a redacted DatasetProfile and retry contract assistance.",
        )
    try:
        safe_profile = sanitize_dataset_profile(dataset_profile)
        payload = {"dataset_profile": safe_profile.to_canonical_dict()}
        result = client.generate(
            task=GptTask.CONTRACT_ASSISTANT,
            prompt_version=CONTRACT_PROMPT_VERSION,
            payload=payload,
            output_model=ContractSuggestionBody,
        )
    except GptPayloadBoundaryError:
        return gpt_error(
            "GPT_PROFILE_PRIVACY_BLOCK",
            "The dataset profile could not cross the bounded GPT data boundary.",
            error_class=ErrorClass.PRIVACY_BLOCK,
            recoverable=True,
            user_action="Remove prohibited metadata and regenerate the redacted profile.",
        )
    except (TypeError, ValueError):
        return gpt_error(
            "GPT_CONTRACT_REQUEST_INVALID",
            "The contract-assistance request could not be constructed safely.",
            error_class=ErrorClass.VALIDATION,
            recoverable=True,
            user_action="Use the fixed contract-assistance interface and retry.",
        )

    if not structured_response_is_bound(
        result,
        task=GptTask.CONTRACT_ASSISTANT,
        prompt_version=CONTRACT_PROMPT_VERSION,
        payload=payload,
        output_model=ContractSuggestionBody,
    ):
        return gpt_error(
            "GPT_CONTRACT_RESPONSE_UNBOUND",
            "The contract-assistance response metadata failed provenance validation.",
            error_class=ErrorClass.SECURITY_BLOCK,
            recoverable=False,
            user_action="Discard the response and retry with the fixed client adapter.",
        )
    if result.metadata.status is not GptCallStatus.SUCCESS or result.output is None:
        return _transport_error(result.metadata.error_code, result.metadata.status.value)
    if not _suggestion_is_valid(
        result.output, tuple(column.name for column in safe_profile.columns)
    ):
        return gpt_error(
            "GPT_CONTRACT_SUGGESTION_INVALID",
            "The contract suggestion failed deterministic column and policy validation.",
            error_class=ErrorClass.API_INVALID_OUTPUT,
            recoverable=True,
            user_action="Review the safe profile and request a new advisory suggestion.",
        )

    body = result.output
    return ContractSuggestion.model_validate(
        {
            "artifact_version": ARTIFACT_VERSION,
            "prompt_version": CONTRACT_PROMPT_VERSION,
            "request": result.request,
            "response": result.metadata,
            "role_suggestions": body.role_suggestions,
            "likely_measurement_unit": body.likely_measurement_unit,
            "unit_evidence": body.unit_evidence,
            "missing_required_inputs": body.missing_required_inputs,
            "clarification_questions": body.clarification_questions,
            "requires_human_confirmation": True,
            "analysis_permitted": False,
        }
    )


def _suggestion_is_valid(
    body: ContractSuggestionBody,
    valid_columns: tuple[str, ...],
) -> bool:
    roles = tuple(item.role for item in body.role_suggestions)
    if roles != _ROLE_ORDER:
        return False
    mapped = tuple(item.column for item in body.role_suggestions if item.column is not None)
    if len(mapped) != len(set(mapped)) or any(column not in valid_columns for column in mapped):
        return False
    # DatasetProfile deliberately contains no measurement-unit assertion. A unit can
    # only be proposed by a future explicitly typed safe-metadata field.
    if body.likely_measurement_unit is not None or body.unit_evidence is not None:
        return False
    required = {
        item.role: item.column
        for item in body.role_suggestions
        if item.role in {ContractRole.QUANTITY, ContractRole.DEPLOYMENT_GROUP}
    }
    if any(required.get(role) is None for role in required) and not body.missing_required_inputs:
        return False
    return body.requires_human_confirmation and not body.analysis_permitted


def _transport_error(error_code: str | None, status: str) -> ErrorEnvelope:
    unavailable = error_code in {
        "OPENAI_AUTHENTICATION_FAILED",
        "OPENAI_API_UNAVAILABLE",
        "OPENAI_CONNECTION_FAILED",
        "OPENAI_MODEL_ACCESS_UNAVAILABLE",
        "OPENAI_MODEL_UNAVAILABLE",
        "OPENAI_RATE_LIMITED",
        "OPENAI_SDK_UNAVAILABLE",
        "OPENAI_TIMEOUT",
        "OPENAI_TRANSIENT_SERVER_ERROR",
    }
    return gpt_error(
        "GPT_CONTRACT_ASSISTANCE_UNAVAILABLE" if unavailable else "GPT_CONTRACT_OUTPUT_REJECTED",
        "Contract narrative assistance is unavailable; no contract was confirmed.",
        error_class=ErrorClass.API_UNAVAILABLE if unavailable else ErrorClass.API_INVALID_OUTPUT,
        recoverable=True,
        user_action="Continue with the manual contract form or retry narrative assistance later.",
        safe_details={"call_status": status, "transport_code": error_code or "UNSPECIFIED"},
    )


__all__ = ["suggest_contract_mapping"]
