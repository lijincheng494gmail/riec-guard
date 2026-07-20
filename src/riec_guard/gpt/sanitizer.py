"""Deterministic outbound payload construction and privacy bounds for GPT stages."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from typing import cast

from riec_guard.contract.models import DatasetProfile
from riec_guard.gpt.models import SafeDatasetProfilePayload

MAX_GPT_PAYLOAD_BYTES = 65_536
MAX_GPT_STRING_LENGTH = 2_000
MAX_GPT_NODES = 1_000

_FORBIDDEN_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "authorization_header",
        "cell_values",
        "dataframe",
        "environment",
        "full_prompt",
        "full_evidence_ledger",
        "local_path",
        "password",
        "predictions",
        "raw_data",
        "raw_rows",
        "residual_array",
        "residuals",
        "row_predictions",
        "safe_examples",
        "sample_rows",
        "sample_values",
        "secret",
        "stack_trace",
        "token",
    }
)
_FORBIDDEN_NORMALIZED_KEYS = frozenset(
    re.sub(r"[^a-z0-9]", "", key.casefold()) for key in _FORBIDDEN_KEYS
)
_LOCAL_PATH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?:~/(?:[^\s\"'<>]+)|(?:\.\.?/)+(?:[^\s\"'<>]+)|"
    r"/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+|"
    r"[A-Za-z]:\\[^\s\"'<>]+|\\\\[^\s\"'<>]+)"
)
_SECRET_VALUE_PATTERN = re.compile(
    r"(?i)(?:\bBearer[ \t]+[A-Za-z0-9._~-]{16,}|"
    r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}|"
    r"(?:AKIA|ASIA)[0-9A-Z]{16}|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"
)


class GptPayloadBoundaryError(ValueError):
    """Safe rejection at the outbound GPT data boundary."""


def canonical_payload_bytes(payload: Mapping[str, object]) -> bytes:
    """Validate and encode one finite bounded JSON object canonically."""

    _validate_payload_node(payload, key=None, state=[0])
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise GptPayloadBoundaryError("GPT payload is not finite JSON") from None
    if len(encoded) > MAX_GPT_PAYLOAD_BYTES:
        raise GptPayloadBoundaryError("GPT payload exceeds the fixed serialized size limit")
    return encoded


def payload_sha256(payload: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_payload_bytes(payload)).hexdigest()


def sanitize_dataset_profile(profile: DatasetProfile) -> SafeDatasetProfilePayload:
    """Project a DatasetProfile without rows, samples, aggregates, paths, or identifiers."""

    if not isinstance(profile, DatasetProfile):
        raise GptPayloadBoundaryError("a typed DatasetProfile is required")
    redaction = profile.privacy_redaction
    if (
        redaction.raw_rows_included
        or redaction.direct_identifiers_included
        or redaction.high_cardinality_values_included
    ):
        raise GptPayloadBoundaryError("dataset profile does not satisfy the outbound redaction")

    value: dict[str, object] = {
        "artifact_version": "1.0.0",
        "payload_version": "safe-dataset-profile.v1",
        "dataset_id": profile.dataset_id,
        "dataset_sha256": profile.dataset_sha256,
        "row_count": profile.row_count,
        "columns": tuple(
            {
                "name": column.name,
                "dtype": column.dtype,
                "missing_fraction": column.missing_fraction,
                "unique_count": column.unique_count,
            }
            for column in profile.column_profiles
        ),
        "semantic_hints": tuple(
            {
                "semantic_role": hint.semantic_role,
                "column": hint.column,
                "confidence": hint.confidence,
                "reasons": tuple(hint.reasons[:5]),
            }
            for hint in profile.candidate_semantic_mappings
        ),
        "raw_rows_included": False,
        "cell_values_included": False,
        "direct_identifiers_included": False,
        "local_paths_included": False,
        "payload_sha256": "0" * 64,
    }
    provisional = SafeDatasetProfilePayload.model_validate(value)
    hash_payload = provisional.to_canonical_dict()
    hash_payload.pop("payload_sha256", None)
    value["payload_sha256"] = payload_sha256(hash_payload)
    result = SafeDatasetProfilePayload.model_validate(value)
    canonical_payload_bytes(result.to_canonical_dict())
    return result


def validate_outbound_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Return a detached JSON object after enforcing all generic outbound bounds."""

    encoded = canonical_payload_bytes(payload)
    decoded = json.loads(encoded.decode("utf-8"))
    if not isinstance(decoded, dict):  # defensive; canonical_payload_bytes requires Mapping
        raise GptPayloadBoundaryError("GPT payload must be a JSON object")
    return cast(dict[str, object], decoded)


def _validate_payload_node(
    value: object,
    *,
    key: str | None,
    state: list[int],
) -> None:
    state[0] += 1
    if state[0] > MAX_GPT_NODES:
        raise GptPayloadBoundaryError("GPT payload exceeds the fixed structural size limit")
    if key is not None:
        normalized_key = re.sub(r"[^a-z0-9]", "", key.casefold())
        if normalized_key in _FORBIDDEN_NORMALIZED_KEYS:
            raise GptPayloadBoundaryError("GPT payload contains a forbidden field")

    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise GptPayloadBoundaryError("GPT payload contains a non-finite number")
        return
    if isinstance(value, str):
        if len(value) > MAX_GPT_STRING_LENGTH:
            raise GptPayloadBoundaryError("GPT payload contains an overlong string")
        if (
            "\x00" in value
            or _LOCAL_PATH_PATTERN.search(value)
            or _SECRET_VALUE_PATTERN.search(value)
        ):
            raise GptPayloadBoundaryError("GPT payload contains prohibited path or credential data")
        return
    if isinstance(value, Mapping):
        for child_key, child in value.items():
            if not isinstance(child_key, str) or not child_key:
                raise GptPayloadBoundaryError("GPT payload object keys must be non-empty strings")
            _validate_payload_node(child, key=child_key, state=state)
        return
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, memoryview)):
        for child in value:
            _validate_payload_node(child, key=None, state=state)
        return
    raise GptPayloadBoundaryError("GPT payload contains a non-JSON object")


__all__ = [
    "GptPayloadBoundaryError",
    "MAX_GPT_PAYLOAD_BYTES",
    "canonical_payload_bytes",
    "payload_sha256",
    "sanitize_dataset_profile",
    "validate_outbound_payload",
]
