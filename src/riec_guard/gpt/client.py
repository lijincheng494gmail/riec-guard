"""Narrow Responses API adapter and deterministic no-network fixture transport."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Protocol, cast

from pydantic import ValidationError

from riec_guard.errors import CanonicalModel
from riec_guard.gpt.models import (
    ARTIFACT_VERSION,
    CLAIM_PROMPT_VERSION,
    CONTRACT_PROMPT_VERSION,
    DEFAULT_GPT_MODEL,
    FixtureFailureMode,
    GptCallStatus,
    GptExecutionMode,
    GptRequestMetadata,
    GptResponseMetadata,
    GptTask,
    GptTokenUsage,
    MEMO_PROMPT_VERSION,
    OutputT,
    StructuredGptResponse,
)
from riec_guard.gpt.prompts import prompt_for_task
from riec_guard.gpt.sanitizer import (
    canonical_payload_bytes,
    payload_sha256,
    validate_outbound_payload,
)

_MAX_OUTPUT_TOKENS = {
    GptTask.CONTRACT_ASSISTANT: 1_200,
    GptTask.DECISION_MEMO: 1_800,
    GptTask.CLAIM_AUDITOR: 1_600,
}
_SAFE_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9_.:-]{1,200}\Z")
FixtureFactory = Callable[[Mapping[str, object], type[CanonicalModel]], object]
_PROMPT_VERSION_BY_TASK = {
    GptTask.CONTRACT_ASSISTANT: CONTRACT_PROMPT_VERSION,
    GptTask.DECISION_MEMO: MEMO_PROMPT_VERSION,
    GptTask.CLAIM_AUDITOR: CLAIM_PROMPT_VERSION,
}


class StructuredGptClient(Protocol):
    """Only GPT transport surface available to interpretation services."""

    def generate(
        self,
        *,
        task: GptTask,
        prompt_version: str,
        payload: Mapping[str, object],
        output_model: type[OutputT],
    ) -> StructuredGptResponse[OutputT]: ...


def structured_response_is_bound(
    result: StructuredGptResponse[OutputT],
    *,
    task: GptTask,
    prompt_version: str,
    payload: Mapping[str, object],
    output_model: type[OutputT],
) -> bool:
    """Verify transport metadata against the exact service-owned request and output."""

    try:
        safe_payload = validate_outbound_payload(payload)
        encoded = canonical_payload_bytes(safe_payload)
        expected_input_hash = payload_sha256(safe_payload)
        request = result.request
        response = result.metadata
        if (
            request.task is not task
            or response.task is not task
            or request.prompt_version != prompt_version
            or response.prompt_version != prompt_version
            or request.requested_model != DEFAULT_GPT_MODEL
            or response.requested_model != DEFAULT_GPT_MODEL
            or request.sanitized_input_sha256 != expected_input_hash
            or response.sanitized_input_sha256 != expected_input_hash
            or request.serialized_payload_bytes != len(encoded)
            or request.execution_mode is not response.execution_mode
            or request.execution_mode is GptExecutionMode.NOT_EXECUTED
        ):
            return False
        if request.execution_mode is GptExecutionMode.FIXTURE:
            if response.returned_model is None or not response.returned_model.startswith(
                "fixture:"
            ):
                return False
        elif response.returned_model is not None and response.returned_model.startswith("fixture:"):
            return False
        if result.output is None:
            return (
                response.status is not GptCallStatus.SUCCESS
                and response.normalized_output_sha256 is None
            )
        return (
            isinstance(result.output, output_model)
            and response.status is GptCallStatus.SUCCESS
            and response.normalized_output_sha256
            == payload_sha256(result.output.to_canonical_dict())
        )
    except (AttributeError, TypeError, ValueError):
        return False


class OpenAIResponsesClient:
    """Lazy, fixed-model, tool-free Structured Outputs adapter."""

    def __init__(
        self,
        *,
        model: str = DEFAULT_GPT_MODEL,
        timeout_seconds: float = 30.0,
        retry_transient_once: bool = True,
        client_factory: Callable[..., object] | None = None,
    ) -> None:
        if model != DEFAULT_GPT_MODEL:
            raise ValueError("the GPT model is fixed and cannot be supplied by end users")
        if not 1.0 <= timeout_seconds <= 60.0:
            raise ValueError("GPT timeout must remain within the fixed bound")
        if type(retry_transient_once) is not bool:
            raise TypeError("retry_transient_once must be boolean")
        self._model = model
        self._timeout_seconds = timeout_seconds
        self._retry_transient_once = retry_transient_once
        self._client_factory = client_factory
        self._sdk_client: object | None = None

    def generate(
        self,
        *,
        task: GptTask,
        prompt_version: str,
        payload: Mapping[str, object],
        output_model: type[OutputT],
    ) -> StructuredGptResponse[OutputT]:
        _validate_task_prompt_version(task, prompt_version)
        safe_payload = validate_outbound_payload(payload)
        encoded = canonical_payload_bytes(safe_payload)
        request = _request_metadata(
            task=task,
            prompt_version=prompt_version,
            payload=safe_payload,
            payload_bytes=len(encoded),
            execution_mode=GptExecutionMode.LIVE,
        )
        maximum_attempts = 2 if self._retry_transient_once else 1
        for attempt in range(1, maximum_attempts + 1):
            try:
                client = self._get_sdk_client()
                responses = getattr(client, "responses")
                response = responses.parse(
                    model=self._model,
                    instructions=prompt_for_task(task),
                    input=[
                        {
                            "role": "user",
                            "content": [
                                {
                                    "type": "input_text",
                                    "text": encoded.decode("utf-8"),
                                }
                            ],
                        }
                    ],
                    text_format=output_model,
                    store=False,
                    max_output_tokens=_MAX_OUTPUT_TOKENS[task],
                    tools=[],
                    parallel_tool_calls=False,
                    stream=False,
                    timeout=self._timeout_seconds,
                )
                return _project_sdk_response(
                    response,
                    request=request,
                    output_model=output_model,
                    attempt_count=attempt,
                )
            except Exception as error:  # SDK exceptions are normalized below without their text.
                code, transient = _classify_sdk_exception(error)
                if transient and attempt < maximum_attempts:
                    continue
                return StructuredGptResponse(
                    output=None,
                    request=request,
                    metadata=_response_metadata(
                        request=request,
                        status=GptCallStatus.ERROR,
                        attempt_count=attempt,
                        execution_mode=GptExecutionMode.LIVE,
                        error_code=code,
                        response_id=_safe_identifier(getattr(error, "request_id", None)),
                    ),
                )
        raise AssertionError("bounded GPT attempts must return")

    def _get_sdk_client(self) -> object:
        if self._sdk_client is not None:
            return self._sdk_client
        import httpx

        timeout = httpx.Timeout(self._timeout_seconds, connect=min(5.0, self._timeout_seconds))
        if self._client_factory is not None:
            client = self._client_factory(timeout=timeout, max_retries=0)
        else:
            from openai import OpenAI

            client = OpenAI(timeout=timeout, max_retries=0)
        self._sdk_client = client
        return client


class FixtureStructuredGptClient:
    """Deterministic fixture transport that never imports or constructs the SDK client."""

    def __init__(
        self,
        fixtures: Mapping[GptTask, CanonicalModel | FixtureFactory],
        *,
        failure_modes: Mapping[GptTask, FixtureFailureMode] | None = None,
    ) -> None:
        self._fixtures = dict(fixtures)
        self._failure_modes = dict(failure_modes or {})
        self._requests: list[GptRequestMetadata] = []

    @property
    def requests(self) -> tuple[GptRequestMetadata, ...]:
        return tuple(self._requests)

    def generate(
        self,
        *,
        task: GptTask,
        prompt_version: str,
        payload: Mapping[str, object],
        output_model: type[OutputT],
    ) -> StructuredGptResponse[OutputT]:
        _validate_task_prompt_version(task, prompt_version)
        safe_payload = validate_outbound_payload(payload)
        encoded = canonical_payload_bytes(safe_payload)
        request = _request_metadata(
            task=task,
            prompt_version=prompt_version,
            payload=safe_payload,
            payload_bytes=len(encoded),
            execution_mode=GptExecutionMode.FIXTURE,
        )
        self._requests.append(request)
        failure = self._failure_modes.get(task, FixtureFailureMode.NONE)
        if failure is not FixtureFailureMode.NONE:
            status, code = _fixture_failure(failure)
            return StructuredGptResponse(
                output=None,
                request=request,
                metadata=_response_metadata(
                    request=request,
                    status=status,
                    attempt_count=1,
                    execution_mode=GptExecutionMode.FIXTURE,
                    error_code=code,
                    response_id=f"resp_fixture_{request.sanitized_input_sha256[:16]}",
                    returned_model="fixture:gpt-5.6",
                    usage=_fixture_usage(encoded, None),
                ),
            )

        fixture = self._fixtures.get(task)
        if fixture is None:
            return StructuredGptResponse(
                output=None,
                request=request,
                metadata=_response_metadata(
                    request=request,
                    status=GptCallStatus.ERROR,
                    attempt_count=1,
                    execution_mode=GptExecutionMode.FIXTURE,
                    error_code="FIXTURE_NOT_CONFIGURED",
                    response_id=f"resp_fixture_{request.sanitized_input_sha256[:16]}",
                    returned_model="fixture:gpt-5.6",
                    usage=_fixture_usage(encoded, None),
                ),
            )
        try:
            raw = fixture(safe_payload, output_model) if callable(fixture) else fixture
            if isinstance(raw, output_model):
                output = cast(OutputT, raw)
            elif isinstance(raw, CanonicalModel):
                output = output_model.model_validate(raw.to_canonical_dict())
            elif isinstance(raw, Mapping):
                output = output_model.model_validate(dict(raw))
            else:
                raise TypeError("fixture output must be a typed model or mapping")
            output_bytes = canonical_payload_bytes(output.to_canonical_dict())
        except (TypeError, ValueError):
            return StructuredGptResponse(
                output=None,
                request=request,
                metadata=_response_metadata(
                    request=request,
                    status=GptCallStatus.ERROR,
                    attempt_count=1,
                    execution_mode=GptExecutionMode.FIXTURE,
                    error_code="FIXTURE_STRUCTURED_OUTPUT_INVALID",
                    response_id=f"resp_fixture_{request.sanitized_input_sha256[:16]}",
                    returned_model="fixture:gpt-5.6",
                    usage=_fixture_usage(encoded, None),
                ),
            )
        return StructuredGptResponse(
            output=output,
            request=request,
            metadata=_response_metadata(
                request=request,
                status=GptCallStatus.SUCCESS,
                attempt_count=1,
                execution_mode=GptExecutionMode.FIXTURE,
                output=output,
                response_id=f"resp_fixture_{request.sanitized_input_sha256[:16]}",
                returned_model="fixture:gpt-5.6",
                usage=_fixture_usage(encoded, output_bytes),
            ),
        )


def _request_metadata(
    *,
    task: GptTask,
    prompt_version: str,
    payload: Mapping[str, object],
    payload_bytes: int,
    execution_mode: GptExecutionMode,
) -> GptRequestMetadata:
    return GptRequestMetadata.model_validate(
        {
            "artifact_version": ARTIFACT_VERSION,
            "task": task,
            "prompt_version": prompt_version,
            "requested_model": DEFAULT_GPT_MODEL,
            "sanitized_input_sha256": payload_sha256(payload),
            "serialized_payload_bytes": payload_bytes,
            "execution_mode": execution_mode,
        }
    )


def _validate_task_prompt_version(task: GptTask, prompt_version: str) -> None:
    if not isinstance(task, GptTask) or prompt_version != _PROMPT_VERSION_BY_TASK.get(task):
        raise ValueError("GPT task and fixed prompt version do not match")


def _response_metadata(
    *,
    request: GptRequestMetadata,
    status: GptCallStatus,
    attempt_count: int,
    execution_mode: GptExecutionMode,
    output: CanonicalModel | None = None,
    response_id: str | None = None,
    returned_model: str | None = None,
    usage: GptTokenUsage | None = None,
    error_code: str | None = None,
) -> GptResponseMetadata:
    output_hash = payload_sha256(output.to_canonical_dict()) if output is not None else None
    return GptResponseMetadata.model_validate(
        {
            "artifact_version": ARTIFACT_VERSION,
            "task": request.task,
            "prompt_version": request.prompt_version,
            "requested_model": DEFAULT_GPT_MODEL,
            "returned_model": returned_model,
            "response_id": response_id,
            "sanitized_input_sha256": request.sanitized_input_sha256,
            "normalized_output_sha256": output_hash,
            "status": status,
            "refusal": status is GptCallStatus.REFUSED,
            "incomplete": status is GptCallStatus.INCOMPLETE,
            "usage": usage or _empty_usage(),
            "attempt_count": attempt_count,
            "execution_mode": execution_mode,
            "error_code": error_code,
        }
    )


def _project_sdk_response(
    response: object,
    *,
    request: GptRequestMetadata,
    output_model: type[OutputT],
    attempt_count: int,
) -> StructuredGptResponse[OutputT]:
    response_id = _safe_identifier(getattr(response, "id", None))
    returned_model = _safe_identifier(getattr(response, "model", None), maximum=100)
    usage = _usage_from_sdk(getattr(response, "usage", None))
    if _response_has_refusal(response):
        return StructuredGptResponse(
            output=None,
            request=request,
            metadata=_response_metadata(
                request=request,
                status=GptCallStatus.REFUSED,
                attempt_count=attempt_count,
                execution_mode=GptExecutionMode.LIVE,
                response_id=response_id,
                returned_model=returned_model,
                usage=usage,
                error_code="MODEL_REFUSAL",
            ),
        )
    status_value = getattr(response, "status", None)
    if status_value != "completed":
        status = GptCallStatus.INCOMPLETE if status_value == "incomplete" else GptCallStatus.ERROR
        return StructuredGptResponse(
            output=None,
            request=request,
            metadata=_response_metadata(
                request=request,
                status=status,
                attempt_count=attempt_count,
                execution_mode=GptExecutionMode.LIVE,
                response_id=response_id,
                returned_model=returned_model,
                usage=usage,
                error_code=(
                    "MODEL_OUTPUT_INCOMPLETE"
                    if status is GptCallStatus.INCOMPLETE
                    else "MODEL_RESPONSE_FAILED"
                ),
            ),
        )
    parsed = getattr(response, "output_parsed", None)
    if not isinstance(parsed, output_model):
        return StructuredGptResponse(
            output=None,
            request=request,
            metadata=_response_metadata(
                request=request,
                status=GptCallStatus.ERROR,
                attempt_count=attempt_count,
                execution_mode=GptExecutionMode.LIVE,
                response_id=response_id,
                returned_model=returned_model,
                usage=usage,
                error_code="MODEL_STRUCTURED_OUTPUT_INVALID",
            ),
        )
    return StructuredGptResponse(
        output=parsed,
        request=request,
        metadata=_response_metadata(
            request=request,
            status=GptCallStatus.SUCCESS,
            attempt_count=attempt_count,
            execution_mode=GptExecutionMode.LIVE,
            output=parsed,
            response_id=response_id,
            returned_model=returned_model,
            usage=usage,
        ),
    )


def _response_has_refusal(response: object) -> bool:
    output = getattr(response, "output", ()) or ()
    for item in output:
        if getattr(item, "type", None) != "message":
            continue
        for content in getattr(item, "content", ()) or ():
            if getattr(content, "type", None) == "refusal":
                return True
    return False


def _usage_from_sdk(usage: object) -> GptTokenUsage:
    return GptTokenUsage.model_validate(
        {
            "input_tokens": _bounded_token_count(getattr(usage, "input_tokens", None)),
            "output_tokens": _bounded_token_count(getattr(usage, "output_tokens", None)),
            "total_tokens": _bounded_token_count(
                getattr(usage, "total_tokens", None), maximum=20_000_000
            ),
        }
    )


def _fixture_usage(input_bytes: bytes, output_bytes: bytes | None) -> GptTokenUsage:
    input_count = max(1, len(input_bytes) // 4)
    output_count = 0 if output_bytes is None else max(1, len(output_bytes) // 4)
    return GptTokenUsage.model_validate(
        {
            "input_tokens": input_count,
            "output_tokens": output_count,
            "total_tokens": input_count + output_count,
        }
    )


def _empty_usage() -> GptTokenUsage:
    return GptTokenUsage.model_validate(
        {"input_tokens": None, "output_tokens": None, "total_tokens": None}
    )


def _bounded_token_count(value: object, *, maximum: int = 10_000_000) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        return None
    return value


def _safe_identifier(value: object, *, maximum: int = 200) -> str | None:
    if not isinstance(value, str) or len(value) > maximum:
        return None
    return value if _SAFE_IDENTIFIER_PATTERN.fullmatch(value) is not None else None


def _fixture_failure(failure: FixtureFailureMode) -> tuple[GptCallStatus, str]:
    return {
        FixtureFailureMode.REFUSAL: (GptCallStatus.REFUSED, "MODEL_REFUSAL"),
        FixtureFailureMode.INCOMPLETE: (GptCallStatus.INCOMPLETE, "MODEL_OUTPUT_INCOMPLETE"),
        FixtureFailureMode.MALFORMED: (GptCallStatus.ERROR, "MODEL_STRUCTURED_OUTPUT_INVALID"),
        FixtureFailureMode.TIMEOUT: (GptCallStatus.ERROR, "OPENAI_TIMEOUT"),
        FixtureFailureMode.AUTHENTICATION: (GptCallStatus.ERROR, "OPENAI_AUTHENTICATION_FAILED"),
        FixtureFailureMode.ACCESS: (GptCallStatus.ERROR, "OPENAI_MODEL_ACCESS_UNAVAILABLE"),
    }[failure]


def _classify_sdk_exception(error: Exception) -> tuple[str, bool]:
    try:
        from openai import (
            APIConnectionError,
            APIResponseValidationError,
            APITimeoutError,
            AuthenticationError,
            InternalServerError,
            NotFoundError,
            OpenAIError,
            PermissionDeniedError,
            RateLimitError,
        )
    except ImportError:
        return "OPENAI_SDK_UNAVAILABLE", False
    if isinstance(error, APITimeoutError):
        return "OPENAI_TIMEOUT", True
    if isinstance(error, APIConnectionError):
        return "OPENAI_CONNECTION_FAILED", True
    if isinstance(error, RateLimitError):
        return "OPENAI_RATE_LIMITED", True
    if isinstance(error, InternalServerError):
        return "OPENAI_TRANSIENT_SERVER_ERROR", True
    if isinstance(error, AuthenticationError):
        return "OPENAI_AUTHENTICATION_FAILED", False
    if isinstance(error, PermissionDeniedError):
        return "OPENAI_MODEL_ACCESS_UNAVAILABLE", False
    if isinstance(error, NotFoundError):
        return "OPENAI_MODEL_UNAVAILABLE", False
    if isinstance(error, APIResponseValidationError):
        return "OPENAI_RESPONSE_SCHEMA_INVALID", False
    if isinstance(error, (ValidationError, TypeError, ValueError)):
        return "MODEL_STRUCTURED_OUTPUT_INVALID", False
    if isinstance(error, OpenAIError):
        return "OPENAI_API_UNAVAILABLE", False
    return "OPENAI_CLIENT_INTERNAL_ERROR", False


__all__ = [
    "FixtureStructuredGptClient",
    "OpenAIResponsesClient",
    "StructuredGptClient",
    "structured_response_is_bound",
]
