"""Deterministic-first, GPT-assisted semantic claim audit."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence

from riec_guard.contract.models import ActionState
from riec_guard.decision.claim_boundary import load_claim_ruleset
from riec_guard.errors import ErrorClass, ErrorEnvelope
from riec_guard.gpt.client import StructuredGptClient, structured_response_is_bound
from riec_guard.gpt.memo import (
    unknown_numeric_tokens,
    validate_evidence_context,
    validate_memo_body,
)
from riec_guard.gpt.models import (
    ARTIFACT_VERSION,
    CLAIM_PROMPT_VERSION,
    MEMO_PROMPT_VERSION,
    ClaimAuditBody,
    ClaimAuditResult,
    ClaimAuditStatus,
    ClaimReview,
    ClaimVerdict,
    DecisionMemo,
    DecisionMemoBody,
    EvidenceContext,
    GptCallStatus,
    GptTask,
    gpt_error,
)
from riec_guard.gpt.sanitizer import (
    GptPayloadBoundaryError,
    payload_sha256,
    validate_outbound_payload,
)

_PROHIBITED_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bachieved savings\b",
        r"\bguaranteed savings\b",
        r"\bwill save\b",
        r"\b(?:is|are|fully) compliant\b",
        r"\bcompliance (?:is|has been) (?:achieved|confirmed|guaranteed)\b",
        r"\bguaranteed safety\b",
        r"\bsafe for production\b",
        r"\boptimal production setpoint\b",
        r"\bzero[- ]risk\b",
        r"\bsuccessful live deployment\b",
        r"\buniversally validated\b",
        r"\bvalidated across all domains\b",
        r"\bcaus(?:e[ds]?|al(?:ly)?)\b.*\bimprov",
    )
)
_VERDICT_PRIORITY = {
    ClaimVerdict.NOT_A_CLAIM: 0,
    ClaimVerdict.SUPPORTED: 1,
    ClaimVerdict.SUPPORTED_WITH_QUALIFICATION: 2,
    ClaimVerdict.OVERSTATED: 3,
    ClaimVerdict.UNSUPPORTED: 4,
    ClaimVerdict.PROHIBITED: 5,
}
_TEXT_EVIDENCE_PATTERN = re.compile(r"\bEV-[A-Z0-9_]{2,16}-[A-F0-9]{12}\b")
_TEXT_FACT_PATTERN = re.compile(r"\b(?:action|gate|policy|profile|protocol|riec)\.[A-Za-z0-9_.]+\b")
_ACTION_LABELS = tuple(state.value for state in ActionState)


def audit_memo_claims(
    *,
    memo: DecisionMemo,
    evidence_context: EvidenceContext,
    client: StructuredGptClient,
) -> ClaimAuditResult | ErrorEnvelope:
    """Apply fixed claim rules, then merge a structured semantic audit conservatively."""

    if not isinstance(memo, DecisionMemo) or not isinstance(evidence_context, EvidenceContext):
        return gpt_error(
            "GPT_CLAIM_AUDIT_INPUT_INVALID",
            "Claim audit requires typed memo and evidence-context artifacts.",
            error_class=ErrorClass.VALIDATION,
            recoverable=True,
            user_action="Use the bounded memo workflow and retry.",
        )
    try:
        validate_evidence_context(evidence_context)
        load_claim_ruleset()
        claims = _extract_claims(memo)
        integrity_blocks = _memo_integrity_blocks(memo, evidence_context, claims)
        deterministic = _deterministic_reviews(claims, evidence_context, integrity_blocks)
        audit_payload = _audit_payload(claims, evidence_context, deterministic)
        result = client.generate(
            task=GptTask.CLAIM_AUDITOR,
            prompt_version=CLAIM_PROMPT_VERSION,
            payload=audit_payload,
            output_model=ClaimAuditBody,
        )
    except GptPayloadBoundaryError:
        return gpt_error(
            "GPT_CLAIM_AUDIT_PRIVACY_BLOCK",
            "The claim audit payload could not cross the bounded GPT data boundary.",
            error_class=ErrorClass.PRIVACY_BLOCK,
            recoverable=True,
            user_action="Regenerate the memo and context from aggregate public-safe facts.",
        )
    except (TypeError, ValueError):
        return gpt_error(
            "GPT_CLAIM_AUDIT_CONTEXT_INVALID",
            "Claim audit inputs failed deterministic identity validation.",
            error_class=ErrorClass.SECURITY_BLOCK,
            recoverable=False,
            user_action="Regenerate the memo from the accepted evidence context.",
        )

    if not structured_response_is_bound(
        result,
        task=GptTask.CLAIM_AUDITOR,
        prompt_version=CLAIM_PROMPT_VERSION,
        payload=audit_payload,
        output_model=ClaimAuditBody,
    ):
        return gpt_error(
            "GPT_CLAIM_RESPONSE_UNBOUND",
            "The claim-audit response metadata failed provenance validation.",
            error_class=ErrorClass.SECURITY_BLOCK,
            recoverable=False,
            user_action="Discard the response and retry with the fixed client adapter.",
        )
    deterministic_blocked = bool(integrity_blocks) or any(
        review.verdict is ClaimVerdict.PROHIBITED for review in deterministic
    )
    if result.metadata.status is not GptCallStatus.SUCCESS or result.output is None:
        return _failed_audit(
            memo,
            evidence_context,
            request=result.request,
            response=result.metadata,
            deterministic=deterministic,
            deterministic_blocked=deterministic_blocked,
            reason="Semantic claim audit was refused, incomplete, or unavailable.",
        )
    model_reviews = result.output.reviews
    if not _model_reviews_are_valid(model_reviews, claims, evidence_context):
        return _failed_audit(
            memo,
            evidence_context,
            request=result.request,
            response=result.metadata,
            deterministic=deterministic,
            deterministic_blocked=True,
            reason="Semantic claim audit output failed deterministic structure validation.",
        )

    merged = tuple(
        _merge_review(deterministic_review, model_review)
        for deterministic_review, model_review in zip(deterministic, model_reviews, strict=True)
    )
    status = _final_status(merged, force_block=bool(integrity_blocks))
    return ClaimAuditResult.model_validate(
        {
            "artifact_version": ARTIFACT_VERSION,
            "prompt_version": CLAIM_PROMPT_VERSION,
            "memo_sha256": payload_sha256(memo.to_canonical_dict()),
            "evidence_context_sha256": evidence_context.payload_sha256,
            "request": result.request,
            "response": result.metadata,
            "status": status,
            "deterministic_validation_status": ("blocked" if deterministic_blocked else "passed"),
            "deterministic_reviews": deterministic,
            "model_reviews": model_reviews,
            "reviews": merged,
            "referenced_evidence_ids": _review_evidence_ids(merged),
            "failure_reason": (
                "Deterministic memo integrity or prohibited-claim rules blocked approval."
                if deterministic_blocked
                else None
            ),
        }
    )


def _extract_claims(memo: DecisionMemo) -> tuple[dict[str, object], ...]:
    all_evidence = _ordered_unique(
        evidence_id for finding in memo.findings for evidence_id in finding.evidence_ids
    )
    all_facts = _ordered_unique(key for finding in memo.findings for key in finding.fact_keys)
    sources: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = [
        (memo.decision_snapshot, all_evidence, all_facts),
        (memo.what_the_evidence_shows, all_evidence, all_facts),
        (memo.why_protocol_choice_matters, all_evidence, all_facts),
        (memo.recommended_next_step, all_evidence, all_facts),
    ]
    sources.extend(
        (finding.statement, finding.evidence_ids, finding.fact_keys) for finding in memo.findings
    )
    if len(sources) > 20 or any(not text.strip() for text, _, _ in sources):
        raise ValueError("memo claims are empty or exceed the fixed bound")
    return tuple(
        {
            "claim_id": f"CLM-{index:03d}",
            "claim_text": text,
            "evidence_ids": evidence_ids,
            "fact_keys": fact_keys,
        }
        for index, (text, evidence_ids, fact_keys) in enumerate(sources, start=1)
    )


def _memo_integrity_blocks(
    memo: DecisionMemo,
    context: EvidenceContext,
    claims: Sequence[Mapping[str, object]],
) -> tuple[str, ...]:
    blocks: list[str] = []
    body = DecisionMemoBody.model_validate(
        {
            "title": memo.title,
            "decision_snapshot": memo.decision_snapshot,
            "what_the_evidence_shows": memo.what_the_evidence_shows,
            "why_protocol_choice_matters": memo.why_protocol_choice_matters,
            "recommended_next_step": memo.recommended_next_step,
            "limitations": memo.limitations,
            "findings": memo.findings,
        }
    )
    if (
        memo.prompt_version != MEMO_PROMPT_VERSION
        or memo.action_state is not context.action_state
        or memo.evidence_context_sha256 != context.payload_sha256
        or memo.request.task is not GptTask.DECISION_MEMO
        or memo.response.task is not GptTask.DECISION_MEMO
        or memo.request.prompt_version != MEMO_PROMPT_VERSION
        or memo.response.prompt_version != MEMO_PROMPT_VERSION
        or memo.response.status is not GptCallStatus.SUCCESS
        or memo.request.sanitized_input_sha256 != memo.response.sanitized_input_sha256
        or memo.response.normalized_output_sha256 != payload_sha256(body.to_canonical_dict())
    ):
        blocks.append("MEMO_IDENTITY_INVALID")
    try:
        validate_memo_body(body, context)
    except ValueError:
        blocks.append("MEMO_SEMANTIC_VALIDATION_FAILED")
    valid_facts = {fact.fact_key for fact in context.facts}
    for claim in claims:
        evidence_ids = set(_string_tuple(claim.get("evidence_ids")))
        fact_keys = set(_string_tuple(claim.get("fact_keys")))
        text = claim.get("claim_text")
        if not evidence_ids.issubset(context.valid_evidence_ids):
            blocks.append("UNKNOWN_EVIDENCE_ID")
        if not fact_keys.issubset(valid_facts):
            blocks.append("UNKNOWN_FACT_KEY")
        if isinstance(text, str):
            if unknown_numeric_tokens(text, context):
                blocks.append("UNSUPPORTED_NUMERIC_TOKEN")
            if any(
                evidence_id not in context.valid_evidence_ids
                for evidence_id in _TEXT_EVIDENCE_PATTERN.findall(text)
            ):
                blocks.append("UNKNOWN_EVIDENCE_ID")
            if any(fact_key not in valid_facts for fact_key in _TEXT_FACT_PATTERN.findall(text)):
                blocks.append("UNKNOWN_FACT_KEY")
    return _ordered_unique(blocks)


def _deterministic_reviews(
    claims: Sequence[Mapping[str, object]],
    context: EvidenceContext,
    integrity_blocks: Sequence[str],
) -> tuple[ClaimReview, ...]:
    conflict = _fact_display(context, "protocol.conflict") == "true"
    reviews: list[ClaimReview] = []
    for claim in claims:
        text = str(claim["claim_text"])
        lowered = text.casefold()
        verdict = ClaimVerdict.SUPPORTED
        reason = "The claim remains bounded to the supplied deterministic context."
        revision: str | None = None
        if integrity_blocks:
            verdict = ClaimVerdict.PROHIBITED
            reason = "Deterministic memo identity, citation, or numeric validation failed."
            revision = "Regenerate the memo from the accepted evidence context."
        elif _is_prohibited_claim(lowered):
            verdict = ClaimVerdict.PROHIBITED
            reason = "The claim crosses the frozen product claim boundary."
            revision = "Remove the prohibited claim; no supporting evidence was supplied."
        elif conflict and _claims_protocol_agreement(lowered):
            verdict = ClaimVerdict.OVERSTATED
            reason = "The accepted protocol context records material disagreement."
            revision = "State that protocol disagreement requires a conservative interpretation."
        elif _unsupported_action_claim(lowered, context.action_state):
            verdict = ClaimVerdict.UNSUPPORTED
            reason = "The claim conflicts with the accepted deterministic action state."
            revision = "Use the accepted action-state wording without adding a pilot interval."
        elif "d0" in lowered and ("action" in lowered or "pilot" in lowered):
            verdict = ClaimVerdict.UNSUPPORTED
            reason = "The D0 mean diagnostic cannot independently support an action."
            revision = "Describe D0 as diagnostic only and cite the accepted action evidence."
        reviews.append(
            ClaimReview.model_validate(
                {
                    "claim_id": claim["claim_id"],
                    "claim_text": text,
                    "verdict": verdict,
                    "evidence_ids": _string_tuple(claim["evidence_ids"]),
                    "fact_keys": _string_tuple(claim["fact_keys"]),
                    "reason": reason,
                    "suggested_revision": revision,
                }
            )
        )
    return tuple(reviews)


def _audit_payload(
    claims: Sequence[Mapping[str, object]],
    context: EvidenceContext,
    deterministic: Sequence[ClaimReview],
) -> dict[str, object]:
    return {
        "claims": tuple(dict(claim) for claim in claims),
        "accepted_action_state": context.action_state.value,
        "allowed_facts": tuple(
            {
                "fact_key": fact.fact_key,
                "display_value": fact.display_value,
                "evidence_ids": fact.evidence_ids,
            }
            for fact in context.facts
        ),
        "valid_evidence_ids": context.valid_evidence_ids,
        "valid_numeric_tokens": context.valid_numeric_tokens,
        "valid_units": context.valid_units,
        "limitations": context.limitations,
        "deterministic_verdict_floor": tuple(
            {"claim_id": review.claim_id, "verdict": review.verdict.value}
            for review in deterministic
        ),
    }


def _model_reviews_are_valid(
    reviews: Sequence[ClaimReview],
    claims: Sequence[Mapping[str, object]],
    context: EvidenceContext,
) -> bool:
    if len(reviews) != len(claims):
        return False
    valid_facts = {fact.fact_key for fact in context.facts}
    for review, claim in zip(reviews, claims, strict=True):
        narrative = " ".join(
            value for value in (review.reason, review.suggested_revision) if value is not None
        )
        if (
            review.claim_id != claim["claim_id"]
            or review.claim_text != claim["claim_text"]
            or tuple(review.evidence_ids) != _string_tuple(claim["evidence_ids"])
            or tuple(review.fact_keys) != _string_tuple(claim["fact_keys"])
            or not set(review.evidence_ids).issubset(context.valid_evidence_ids)
            or not set(review.fact_keys).issubset(valid_facts)
            or not review.reason.strip()
            or unknown_numeric_tokens(narrative, context)
            or any(
                evidence_id not in context.valid_evidence_ids
                for evidence_id in _TEXT_EVIDENCE_PATTERN.findall(narrative)
            )
            or any(
                fact_key not in valid_facts for fact_key in _TEXT_FACT_PATTERN.findall(narrative)
            )
            or any(
                label != context.action_state.value and label in narrative
                for label in _ACTION_LABELS
            )
        ):
            return False
        try:
            validate_outbound_payload({"audit_text": narrative})
        except GptPayloadBoundaryError:
            return False
    return True


def _merge_review(deterministic: ClaimReview, model: ClaimReview) -> ClaimReview:
    winner = (
        deterministic
        if _VERDICT_PRIORITY[deterministic.verdict] >= _VERDICT_PRIORITY[model.verdict]
        else model
    )
    return ClaimReview.model_validate(
        {
            "claim_id": deterministic.claim_id,
            "claim_text": deterministic.claim_text,
            "verdict": winner.verdict,
            "evidence_ids": deterministic.evidence_ids,
            "fact_keys": deterministic.fact_keys,
            "reason": winner.reason,
            "suggested_revision": winner.suggested_revision,
        }
    )


def _failed_audit(
    memo: DecisionMemo,
    context: EvidenceContext,
    *,
    request: object,
    response: object,
    deterministic: tuple[ClaimReview, ...],
    deterministic_blocked: bool,
    reason: str,
) -> ClaimAuditResult:
    return ClaimAuditResult.model_validate(
        {
            "artifact_version": ARTIFACT_VERSION,
            "prompt_version": CLAIM_PROMPT_VERSION,
            "memo_sha256": payload_sha256(memo.to_canonical_dict()),
            "evidence_context_sha256": context.payload_sha256,
            "request": request,
            "response": response,
            "status": ClaimAuditStatus.BLOCKED,
            "deterministic_validation_status": ("blocked" if deterministic_blocked else "passed"),
            "deterministic_reviews": deterministic,
            "model_reviews": (),
            "reviews": deterministic,
            "referenced_evidence_ids": _review_evidence_ids(deterministic),
            "failure_reason": reason,
        }
    )


def _final_status(
    reviews: Sequence[ClaimReview],
    *,
    force_block: bool,
) -> ClaimAuditStatus:
    verdicts = {review.verdict for review in reviews}
    if force_block or ClaimVerdict.PROHIBITED in verdicts:
        return ClaimAuditStatus.BLOCKED
    if verdicts & {
        ClaimVerdict.UNSUPPORTED,
        ClaimVerdict.OVERSTATED,
        ClaimVerdict.SUPPORTED_WITH_QUALIFICATION,
    }:
        return ClaimAuditStatus.REVISE
    return ClaimAuditStatus.PASS


def _is_prohibited_claim(lowered: str) -> bool:
    if any(pattern.search(lowered) for pattern in _PROHIBITED_PATTERNS):
        return True
    return "production setpoint" in lowered and "not a production setpoint" not in lowered


def _claims_protocol_agreement(lowered: str) -> bool:
    return "full agreement" in lowered or "protocols agree" in lowered


def _unsupported_action_claim(lowered: str, state: ActionState) -> bool:
    if state not in {
        ActionState.DIAGNOSE_PROCESS_FIRST,
        ActionState.INSUFFICIENT_EVIDENCE,
        ActionState.NO_ACTIONABLE_HEADROOM,
        ActionState.INVALID_CONTRACT,
    }:
        return False
    supports_pilot = (
        "supports a pilot" in lowered
        or "pilot interval is supported" in lowered
        or "proceed with a pilot" in lowered
    )
    return supports_pilot and "no pilot" not in lowered


def _fact_display(context: EvidenceContext, key: str) -> str | None:
    return next((fact.display_value for fact in context.facts if fact.fact_key == key), None)


def _review_evidence_ids(reviews: Sequence[ClaimReview]) -> tuple[str, ...]:
    return _ordered_unique(evidence_id for review in reviews for evidence_id in review.evidence_ids)


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)) or not all(isinstance(item, str) for item in value):
        raise ValueError("claim citations must be bounded string arrays")
    return tuple(value)


def _ordered_unique(values: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        if value not in result:
            result.append(value)
    return tuple(result)


__all__ = ["audit_memo_claims"]
