from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from pydantic import ValidationError

import riec_guard.evidence.ledger as ledger_module
from riec_guard.evidence.ids import (
    CanonicalJsonError,
    EvidenceError,
    EvidenceErrorCode,
    canonical_json_bytes,
    canonical_sha256,
    create_evidence_item,
    evidence_identity,
    sha256_file,
    verify_evidence_item,
)
from riec_guard.evidence.ledger import (
    EvidenceLedgerBuilder,
    RunBoundEvidence,
    bind_ledger_items,
    verify_ledger,
)
from riec_guard.evidence.models import EvidenceItem, EvidenceLedger
from riec_guard.evidence.provenance import validate_provenance_graph

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_PATH = REPOSITORY_ROOT / "schemas/examples/evidence_ledger.example.json"
INPUT_HASH = "1" * 64
CONTRACT_HASH = "2" * 64
SOURCE_HASH = "3" * 64
RUN_ID = "RUN-ABCDEF123456"
FROZEN_LEDGER_HASH = "b533abc49c9438e59ed493e94b6c855b41bd8e87ab7e0646411d951dc06c9ca7"


def _fields(**changes: object) -> dict[str, object]:
    fields: dict[str, object] = {
        "component": "PROFILE",
        "kind": "statistic",
        "status": "ok",
        "statement": "The aggregate profile contains three rows.",
        "value": {"n_rows": 3, "mean": 1.25},
        "unit": None,
        "source_refs": [
            {
                "artifact_id": "fixture.v1",
                "artifact_sha256": SOURCE_HASH,
                "locator": "public synthetic fixture",
            }
        ],
        "parent_evidence_ids": [],
        "input_sha256": INPUT_HASH,
        "contract_sha256": CONTRACT_HASH,
        "implementation_version": "1.0.0",
        "created_at": "2026-07-19T00:00:00Z",
    }
    fields.update(changes)
    return fields


def _item(**changes: object) -> EvidenceItem:
    return create_evidence_item(**_fields(**changes))  # type: ignore[arg-type]


def _append_new(
    builder: EvidenceLedgerBuilder,
    **changes: object,
) -> RunBoundEvidence:
    return builder.append_new(**_fields(**changes))  # type: ignore[arg-type]


def _bind_items(
    ledger: EvidenceLedger,
    *,
    expected_source_run_id: str,
    expected_ledger_sha256: str | None = None,
) -> tuple[RunBoundEvidence, ...]:
    trusted_hash = (
        verify_ledger(ledger).ledger_canonical_sha256
        if expected_ledger_sha256 is None
        else expected_ledger_sha256
    )
    return bind_ledger_items(
        ledger,
        expected_source_run_id=expected_source_run_id,
        expected_ledger_sha256=trusted_hash,
    )


def _example_payload() -> dict[str, object]:
    value = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _expect_code(error: pytest.ExceptionInfo[EvidenceError], code: EvidenceErrorCode) -> None:
    assert error.value.code is code


def test_canonical_json_is_deterministic_under_key_reordering() -> None:
    left = {"b": [2, 1], "a": {"z": True, "x": None}}
    right = {"a": {"x": None, "z": True}, "b": [2, 1]}
    assert canonical_json_bytes(left) == canonical_json_bytes(right)
    assert canonical_sha256(left) == canonical_sha256(right)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_canonical_json_rejects_each_nonfinite_number(value: float) -> None:
    with pytest.raises(CanonicalJsonError):
        canonical_json_bytes({"value": value})


@pytest.mark.parametrize(
    "value",
    [object(), b"bytes", {"set"}, Path("logical")],
)
def test_canonical_json_rejects_unsupported_python_objects(value: object) -> None:
    with pytest.raises(CanonicalJsonError):
        canonical_json_bytes(value)


def test_canonical_json_rejects_tuple_as_non_json_native() -> None:
    with pytest.raises(CanonicalJsonError):
        canonical_json_bytes((1, 2))


def test_canonical_json_rejects_reference_cycle() -> None:
    value: list[object] = []
    value.append(value)
    with pytest.raises(CanonicalJsonError):
        canonical_json_bytes(value)


def test_canonical_json_preserves_utf8_and_compact_separators() -> None:
    assert canonical_json_bytes({"label": "量"}) == '{"label":"量"}'.encode()


def test_same_evidence_content_produces_same_hash_and_id() -> None:
    first = _item()
    second = _item()
    assert first.content_sha256 == second.content_sha256
    assert first.evidence_id == second.evidence_id


def test_different_statement_changes_hash_and_id() -> None:
    first = _item()
    second = _item(statement="The aggregate profile contains four rows.")
    assert first.content_sha256 != second.content_sha256
    assert first.evidence_id != second.evidence_id


def test_different_value_changes_hash_and_id() -> None:
    first = _item()
    second = _item(value={"n_rows": 4, "mean": 1.25})
    assert first.content_sha256 != second.content_sha256
    assert first.evidence_id != second.evidence_id


def test_different_parent_list_changes_hash_and_id() -> None:
    first = _item()
    second = _item(parent_evidence_ids=["EV-SYSTEM-AAAAAAAAAAAA"])
    assert first.content_sha256 != second.content_sha256
    assert first.evidence_id != second.evidence_id


def test_parent_array_order_remains_identity_significant() -> None:
    parents = ["EV-SYSTEM-AAAAAAAAAAAA", "EV-SYSTEM-BBBBBBBBBBBB"]
    first = _item(parent_evidence_ids=parents)
    second = _item(parent_evidence_ids=list(reversed(parents)))
    assert first.evidence_id != second.evidence_id


def test_different_source_ref_changes_hash_and_id() -> None:
    first = _item()
    second = _item(
        source_refs=[
            {
                "artifact_id": "fixture.v2",
                "artifact_sha256": SOURCE_HASH,
                "locator": "public synthetic fixture",
            }
        ]
    )
    assert first.evidence_id != second.evidence_id


def test_source_ref_order_remains_identity_significant() -> None:
    refs = [
        {
            "artifact_id": "fixture.v1",
            "artifact_sha256": SOURCE_HASH,
            "locator": "first source",
        },
        {
            "artifact_id": "contract.json",
            "artifact_sha256": CONTRACT_HASH,
            "locator": "second source",
        },
    ]
    assert (
        _item(source_refs=refs).evidence_id != _item(source_refs=list(reversed(refs))).evidence_id
    )


def test_different_contract_hash_changes_hash_and_id() -> None:
    assert _item().evidence_id != _item(contract_sha256="4" * 64).evidence_id


def test_different_implementation_version_changes_hash_and_id() -> None:
    assert _item().evidence_id != _item(implementation_version="1.0.1").evidence_id


def test_different_created_at_does_not_change_hash_or_id() -> None:
    first = _item(created_at="2026-07-19T00:00:00Z")
    second = _item(created_at="2026-07-20T00:00:00Z")
    assert first.content_sha256 == second.content_sha256
    assert first.evidence_id == second.evidence_id


def test_explicit_null_and_nested_value_structure_are_preserved() -> None:
    item = _item(value={"result": None, "values": [1, "two"]})
    assert item.to_canonical_dict()["value"] == {
        "result": None,
        "values": [1, "two"],
    }


def test_null_failed_value_is_not_coerced_to_zero() -> None:
    item = _item(kind="failure", status="blocking", value=None)
    assert item.to_canonical_dict()["value"] is None


def test_nested_nonfinite_evidence_value_is_rejected() -> None:
    with pytest.raises(EvidenceError) as caught:
        _item(value={"nested": [1.0, float("nan")]})
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT)


def test_tuple_evidence_value_is_rejected_instead_of_coerced() -> None:
    with pytest.raises(EvidenceError) as caught:
        _item(value=(1, 2))
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT)


def test_array_value_outside_frozen_item_schema_is_rejected() -> None:
    with pytest.raises(EvidenceError) as caught:
        _item(value=[True])
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_SCHEMA_INVALID)


def test_all_frozen_example_hashes_and_ids_reproduce() -> None:
    ledger = EvidenceLedger.model_validate(_example_payload())
    for item in ledger.items:
        identity = evidence_identity(item)
        assert identity.content_sha256 == item.content_sha256
        assert identity.evidence_id == item.evidence_id


def test_frozen_profile_required_example_identity_is_exact() -> None:
    ledger = EvidenceLedger.model_validate(_example_payload())
    profile = ledger.items[0]
    assert profile.content_sha256.startswith("91c7db559190")
    assert profile.evidence_id == "EV-PROFILE-91C7DB559190"


def test_full_hash_is_lowercase_and_id_suffix_is_uppercase() -> None:
    item = _item()
    assert item.content_sha256 == item.content_sha256.lower()
    assert item.evidence_id.rsplit("-", 1)[1] == item.evidence_id.rsplit("-", 1)[1].upper()


def test_incoming_wrong_content_hash_is_rejected() -> None:
    item = _item().model_copy(update={"content_sha256": "0" * 64})
    with pytest.raises(EvidenceError) as caught:
        verify_evidence_item(item)
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_HASH_MISMATCH)


def test_incoming_wrong_evidence_id_is_rejected() -> None:
    item = _item().model_copy(update={"evidence_id": "EV-PROFILE-AAAAAAAAAAAA"})
    with pytest.raises(EvidenceError) as caught:
        verify_evidence_item(item)
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_ID_INVALID)


def test_evidence_id_component_mismatch_is_rejected() -> None:
    item = _item().model_copy(update={"evidence_id": "EV-RIEC-AAAAAAAAAAAA"})
    with pytest.raises(EvidenceError) as caught:
        verify_evidence_item(item)
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_COMPONENT_MISMATCH)


def test_duplicate_parent_id_is_rejected() -> None:
    parent = "EV-SYSTEM-AAAAAAAAAAAA"
    with pytest.raises(EvidenceError) as caught:
        _item(parent_evidence_ids=[parent, parent])
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_DUPLICATE_PARENT)


def test_self_parenting_is_rejected() -> None:
    item = _item()
    self_parent = item.model_copy(update={"parent_evidence_ids": (item.evidence_id,)})
    with pytest.raises(EvidenceError) as caught:
        verify_evidence_item(self_parent)
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_SELF_PARENT)


def test_missing_parent_is_rejected_at_finalization() -> None:
    builder = EvidenceLedgerBuilder(RUN_ID)
    _append_new(builder, parent_evidence_ids=["EV-SYSTEM-AAAAAAAAAAAA"])
    with pytest.raises(EvidenceError) as caught:
        builder.finalize()
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_PARENT_NOT_FOUND)


def _graph_item(evidence_id: str, parents: tuple[str, ...]) -> EvidenceItem:
    return _item().model_copy(
        update={
            "evidence_id": evidence_id,
            "content_sha256": "0" * 64,
            "parent_evidence_ids": parents,
        }
    )


def test_two_node_cycle_is_rejected() -> None:
    left = "EV-SYSTEM-AAAAAAAAAAAA"
    right = "EV-SYSTEM-BBBBBBBBBBBB"
    with pytest.raises(EvidenceError) as caught:
        validate_provenance_graph((_graph_item(left, (right,)), _graph_item(right, (left,))))
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_GRAPH_CYCLE)


def test_multi_node_cycle_is_rejected() -> None:
    first = "EV-SYSTEM-AAAAAAAAAAAA"
    second = "EV-SYSTEM-BBBBBBBBBBBB"
    third = "EV-SYSTEM-CCCCCCCCCCCC"
    items = (
        _graph_item(first, (third,)),
        _graph_item(second, (first,)),
        _graph_item(third, (second,)),
    )
    with pytest.raises(EvidenceError) as caught:
        validate_provenance_graph(items)
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_GRAPH_CYCLE)


def _valid_chain() -> tuple[EvidenceItem, EvidenceItem, EvidenceItem]:
    first = _item(statement="First aggregate.")
    second = _item(
        component="RIEC",
        statement="Second aggregate.",
        parent_evidence_ids=[first.evidence_id],
    )
    third = _item(
        component="ACTION",
        kind="decision_reason",
        status="warning",
        statement="Third aggregate.",
        parent_evidence_ids=[second.evidence_id],
    )
    return first, second, third


def test_valid_acyclic_chain_passes_and_supports_traversal() -> None:
    first, second, third = _valid_chain()
    graph = validate_provenance_graph((first, second, third))
    assert graph.direct_ancestors(third.evidence_id) == (second.evidence_id,)
    assert graph.ancestors(third.evidence_id) == tuple(
        sorted((first.evidence_id, second.evidence_id))
    )
    assert graph.descendants(first.evidence_id) == tuple(
        sorted((second.evidence_id, third.evidence_id))
    )


def test_imported_out_of_order_acyclic_ledger_passes() -> None:
    first, second, third = _valid_chain()
    source = EvidenceLedger.model_validate(
        {
            "schema_version": "1.0.0",
            "run_id": RUN_ID,
            "canonicalization": _example_payload()["canonicalization"],
            "items": [
                first.to_canonical_dict(),
                second.to_canonical_dict(),
                third.to_canonical_dict(),
            ],
        }
    )
    bound_by_id = {
        record.item.evidence_id: record
        for record in _bind_items(source, expected_source_run_id=RUN_ID)
    }
    builder = EvidenceLedgerBuilder(RUN_ID)
    for item in (third, first, second):
        builder.append(bound_by_id[item.evidence_id])
    ledger = builder.finalize()
    result = verify_ledger(
        ledger,
        expected_run_id=RUN_ID,
        bound_items=builder.bound_items,
    )
    assert result.item_count == 3
    assert result.run_ownership_verified


def test_duplicate_evidence_id_is_rejected() -> None:
    item = _item()
    ledger = EvidenceLedger.model_construct(
        schema_version="1.0.0",
        run_id=RUN_ID,
        canonicalization=EvidenceLedger.model_validate(_example_payload()).canonicalization,
        items=(item, item),
    )
    with pytest.raises(EvidenceError) as caught:
        verify_ledger(ledger)
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_DUPLICATE_ID)


def test_canonically_identical_repeated_append_is_idempotent() -> None:
    builder = EvidenceLedgerBuilder(RUN_ID)
    first = _append_new(builder, created_at="2026-07-19T00:00:00Z")
    second = _append_new(builder, created_at="2026-07-20T00:00:00Z")
    assert second is first
    assert len(builder.items) == 1


def test_same_id_with_different_content_fails_as_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = EvidenceLedgerBuilder(RUN_ID)
    original = _append_new(builder)
    altered = original.item.model_copy(update={"statement": "Different aggregate statement."})
    monkeypatch.setattr(ledger_module, "create_evidence_item", lambda **_fields: altered)
    with pytest.raises(EvidenceError) as caught:
        _append_new(builder)
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_COLLISION)


def test_append_after_finalization_is_rejected() -> None:
    builder = EvidenceLedgerBuilder(RUN_ID)
    _append_new(builder)
    builder.finalize()
    with pytest.raises(EvidenceError) as caught:
        _append_new(builder, statement="Another aggregate.")
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_LEDGER_FINALIZED)


def test_empty_ledger_cannot_finalize() -> None:
    with pytest.raises(EvidenceError) as caught:
        EvidenceLedgerBuilder(RUN_ID).finalize()
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_SCHEMA_INVALID)


def test_final_ledger_validates_against_canonical_model_and_schema() -> None:
    builder = EvidenceLedgerBuilder(RUN_ID)
    _append_new(builder)
    ledger = builder.finalize()
    assert EvidenceLedger.model_validate(ledger.to_canonical_dict()) == ledger


def test_frozen_evidence_ledger_example_verifies_completely() -> None:
    ledger = EvidenceLedger.model_validate(_example_payload())
    structural = verify_ledger(ledger)
    assert not structural.run_ownership_verified
    bound = _bind_items(
        ledger,
        expected_source_run_id="RUN-F0DE9EA43245",
        expected_ledger_sha256=FROZEN_LEDGER_HASH,
    )
    result = verify_ledger(
        ledger,
        expected_run_id="RUN-F0DE9EA43245",
        bound_items=bound,
    )
    assert result.item_count == 11
    assert result.graph.node_count == 11
    assert result.graph.edge_count == 18
    assert result.ledger_canonical_sha256 == (FROZEN_LEDGER_HASH)
    assert result.run_ownership_verified


def test_source_ref_absolute_path_is_rejected() -> None:
    absolute = "/" + "Users" + "/example/source.csv"
    with pytest.raises(EvidenceError) as caught:
        _item(
            source_refs=[
                {
                    "artifact_id": "fixture.v1",
                    "artifact_sha256": SOURCE_HASH,
                    "locator": absolute,
                }
            ]
        )
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_SOURCE_REF_INVALID)


def test_source_ref_traversal_is_rejected() -> None:
    traversal = "artifacts/" + ".." + "/source.csv"
    with pytest.raises(EvidenceError) as caught:
        _item(
            source_refs=[
                {
                    "artifact_id": "fixture.v1",
                    "artifact_sha256": SOURCE_HASH,
                    "locator": traversal,
                }
            ]
        )
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_SOURCE_REF_INVALID)


def test_duplicate_source_artifact_identity_is_rejected() -> None:
    reference = {
        "artifact_id": "fixture.v1",
        "artifact_sha256": SOURCE_HASH,
        "locator": "public source",
    }
    with pytest.raises(EvidenceError) as caught:
        _item(source_refs=[reference, dict(reference)])
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_SOURCE_REF_INVALID)


def test_secret_like_evidence_metadata_is_rejected() -> None:
    sensitive_key = "api" + "_key"
    sensitive_value = "sk-" + "A" * 16
    with pytest.raises(EvidenceError) as caught:
        _item(value={sensitive_key: sensitive_value})
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT)


@pytest.mark.parametrize(
    "secret",
    [
        "AKIA" + "A" * 16,
        "ghp_" + "a" * 20,
        "github_pat_" + "a" * 20,
    ],
)
def test_cloud_and_source_control_credentials_are_rejected(secret: str) -> None:
    with pytest.raises(EvidenceError) as caught:
        _item(value={"note": secret})
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT)


@pytest.mark.parametrize(
    "local_path",
    [
        "file:" + "/" * 3 + "Users/operator/private.csv",
        "file:" + "/" + "Users/operator/private.csv",
        "path:" + "/" + "Users/operator/private.csv",
        "path:C" + ":" + "/" + "Users/operator/private.csv",
        "path:" + "\\" * 2 + "server\\share\\private.csv",
        "~/private.csv",
        "~operator/private.csv",
        "../private.csv",
    ],
)
def test_local_path_aliases_are_rejected(local_path: str) -> None:
    with pytest.raises(EvidenceError) as caught:
        _item(value={"note": local_path})
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT)


def test_raw_row_like_evidence_metadata_is_rejected() -> None:
    with pytest.raises(EvidenceError) as caught:
        _item(value={"raw_rows": [[1, 2]]})
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT)


@pytest.mark.parametrize("key", ["rows", "records"])
def test_ambiguous_row_container_keys_are_rejected(key: str) -> None:
    with pytest.raises(EvidenceError) as caught:
        _item(value={key: [[1, 2]]})
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT)


@pytest.mark.parametrize(
    "key",
    [
        "raw_rows_copy",
        "uploaded_rows_payload",
        "direct_identifiers_backup",
        "row_data_copy",
        "raw_data_payload",
    ],
)
def test_sensitive_row_alias_keys_are_rejected(key: str) -> None:
    with pytest.raises(EvidenceError) as caught:
        _item(value={key: [[1, 2]]})
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT)


def test_direct_identifier_like_evidence_metadata_is_rejected() -> None:
    identifier = "person" + "@" + "example.com"
    with pytest.raises(EvidenceError) as caught:
        _item(value={"note": identifier})
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT)


def test_root_level_absolute_path_is_rejected() -> None:
    root_level_path = "/" + "tmp"
    with pytest.raises(EvidenceError) as caught:
        _item(value={"note": root_level_path})
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT)


def test_sensitive_suffix_and_unsafe_mapping_key_are_rejected() -> None:
    with pytest.raises(EvidenceError) as caught:
        _item(value={"service_api" + "_key": "placeholder"})
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT)
    unsafe_key = "/" + "tmp"
    with pytest.raises(EvidenceError) as caught_path:
        _item(value={unsafe_key: "value"})
    _expect_code(caught_path, EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT)


def test_control_character_in_mapping_key_is_rejected() -> None:
    with pytest.raises(EvidenceError) as caught:
        _item(value={"bad\x00key": 1})
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT)


@pytest.mark.parametrize(
    "aggregate",
    [{"n_rows": 3}, {"row_count": 3}, {"min_rows": 3}],
)
def test_legitimate_aggregate_row_keys_remain_permitted(aggregate: dict[str, int]) -> None:
    assert _item(value=aggregate).to_canonical_dict()["value"] == aggregate


def test_public_error_does_not_echo_secret_or_absolute_path() -> None:
    unsafe = "/" + "home" + "/person/private.csv"
    with pytest.raises(EvidenceError) as caught:
        _item(value={"note": unsafe})
    public = str(caught.value)
    assert unsafe not in public
    assert "person" not in public


def test_finalized_ledger_and_nested_payload_are_immutable() -> None:
    builder = EvidenceLedgerBuilder(RUN_ID)
    _append_new(builder)
    ledger = builder.finalize()
    with pytest.raises(ValidationError):
        ledger.run_id = "RUN-BBBBBBBBBBBB"  # type: ignore[misc]
    with pytest.raises(TypeError):
        ledger.items[0].value["n_rows"] = 4  # type: ignore[index]


def test_builder_detaches_caller_owned_mutable_evidence_value() -> None:
    alias = {"n_rows": 3, "mean": 1.25}
    builder = EvidenceLedgerBuilder(RUN_ID)
    stored = _append_new(builder, value=alias)
    ledger = builder.finalize()
    alias["n_rows"] = 999
    assert stored.item.value["n_rows"] == 3  # type: ignore[index]
    assert ledger.items[0].value["n_rows"] == 3  # type: ignore[index]
    assert builder.finalize() is ledger


def test_verification_order_and_diagnostics_are_deterministic() -> None:
    first, second, third = _valid_chain()
    orders = []
    for items in ((first, second, third), (third, first, second), (second, third, first)):
        orders.append(validate_provenance_graph(items).topological_order)
    assert orders[0] == orders[1] == orders[2]
    missing = _item(parent_evidence_ids=["EV-SYSTEM-AAAAAAAAAAAA"])
    messages = []
    for _ in range(2):
        with pytest.raises(EvidenceError) as caught:
            validate_provenance_graph((missing,))
        messages.append((caught.value.code, str(caught.value)))
    assert messages[0] == messages[1]


def test_invalid_import_diagnostics_do_not_depend_on_item_order() -> None:
    canonicalization = EvidenceLedger.model_validate(_example_payload()).canonicalization
    hash_invalid = _item().model_copy(
        update={
            "evidence_id": "EV-PROFILE-AAAAAAAAAAAA",
            "content_sha256": "0" * 64,
        }
    )
    component_invalid = _item().model_copy(
        update={
            "evidence_id": "EV-RIEC-BBBBBBBBBBBB",
            "content_sha256": "0" * 64,
        }
    )
    diagnostics = []
    for items in ((hash_invalid, component_invalid), (component_invalid, hash_invalid)):
        ledger = EvidenceLedger.model_construct(
            schema_version="1.0.0",
            run_id=RUN_ID,
            canonicalization=canonicalization,
            items=items,
        )
        with pytest.raises(EvidenceError) as caught:
            verify_ledger(ledger)
        diagnostics.append((caught.value.code, str(caught.value)))
    assert diagnostics[0] == diagnostics[1]


def test_expected_run_mismatch_is_rejected() -> None:
    builder = EvidenceLedgerBuilder(RUN_ID)
    _append_new(builder)
    with pytest.raises(EvidenceError) as caught:
        verify_ledger(
            builder.finalize(),
            expected_run_id="RUN-BBBBBBBBBBBB",
            bound_items=builder.bound_items,
        )
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_RUN_MISMATCH)


def test_same_run_bound_import_passes_with_verified_ownership() -> None:
    source = EvidenceLedgerBuilder(RUN_ID)
    _append_new(source)
    source_ledger = source.finalize()
    target = EvidenceLedgerBuilder(RUN_ID)
    for record in _bind_items(source_ledger, expected_source_run_id=RUN_ID):
        target.append(record)
    target_ledger = target.finalize()
    result = verify_ledger(
        target_ledger,
        expected_run_id=RUN_ID,
        bound_items=target.bound_items,
    )
    assert result.item_count == 1
    assert result.run_ownership_verified


def test_cross_run_bound_import_fails_before_idempotence() -> None:
    source = EvidenceLedgerBuilder("RUN-AAAAAAAAAAAA")
    _append_new(source)
    foreign_ledger = source.finalize()
    foreign = _bind_items(
        foreign_ledger,
        expected_source_run_id="RUN-AAAAAAAAAAAA",
    )[0]
    target = EvidenceLedgerBuilder("RUN-BBBBBBBBBBBB")
    with pytest.raises(EvidenceError) as caught:
        target.append(foreign)
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_RUN_MISMATCH)
    assert target.items == ()


def test_naked_imported_item_without_ownership_context_fails() -> None:
    target = EvidenceLedgerBuilder(RUN_ID)
    with pytest.raises(EvidenceError) as caught:
        target.append(_item())
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_RUN_MISMATCH)
    assert target.items == ()


def test_public_run_bound_record_construction_is_sealed() -> None:
    with pytest.raises(EvidenceError) as caught:
        RunBoundEvidence(RUN_ID, _item())
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_RUN_MISMATCH)


def test_run_bound_record_cannot_be_rebound_with_dataclasses_replace() -> None:
    source = EvidenceLedgerBuilder("RUN-AAAAAAAAAAAA")
    foreign = _append_new(source)
    with pytest.raises(EvidenceError) as caught:
        replace(foreign, run_id="RUN-BBBBBBBBBBBB")
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_RUN_MISMATCH)


def test_run_bound_record_detects_direct_run_id_mutation() -> None:
    source = EvidenceLedgerBuilder("RUN-AAAAAAAAAAAA")
    foreign = _append_new(source)
    object.__setattr__(foreign, "run_id", "RUN-BBBBBBBBBBBB")
    target = EvidenceLedgerBuilder("RUN-BBBBBBBBBBBB")
    with pytest.raises(EvidenceError) as caught:
        target.append(foreign)
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_RUN_MISMATCH)


def test_run_bound_record_detects_direct_item_replacement() -> None:
    source = EvidenceLedgerBuilder(RUN_ID)
    bound = _append_new(source)
    object.__setattr__(bound, "item", _item(statement="Replacement aggregate."))
    target = EvidenceLedgerBuilder(RUN_ID)
    with pytest.raises(EvidenceError) as caught:
        target.append(bound)
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_RUN_MISMATCH)


def test_binding_requires_trusted_source_context() -> None:
    source = EvidenceLedger.model_validate(_example_payload())
    with pytest.raises(EvidenceError) as caught:
        bind_ledger_items(source)
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_RUN_MISMATCH)


@pytest.mark.parametrize("reconstruct", [False, True])
def test_relabelled_source_ledger_cannot_mint_target_ownership(reconstruct: bool) -> None:
    source = EvidenceLedger.model_validate(_example_payload())
    if reconstruct:
        payload = source.to_canonical_dict()
        payload["run_id"] = RUN_ID
        relabelled = EvidenceLedger.model_validate(payload)
    else:
        relabelled = source.model_copy(update={"run_id": RUN_ID})
    with pytest.raises(EvidenceError) as caught:
        bind_ledger_items(
            relabelled,
            expected_source_run_id="RUN-F0DE9EA43245",
            expected_ledger_sha256=FROZEN_LEDGER_HASH,
        )
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_RUN_MISMATCH)


def test_all_frozen_items_cannot_be_rebound_to_another_run() -> None:
    source = EvidenceLedger.model_validate(_example_payload())
    assert source.run_id == "RUN-F0DE9EA43245"
    target = EvidenceLedgerBuilder(RUN_ID)
    for foreign in _bind_items(
        source,
        expected_source_run_id="RUN-F0DE9EA43245",
        expected_ledger_sha256=FROZEN_LEDGER_HASH,
    ):
        with pytest.raises(EvidenceError) as caught:
            target.append(foreign)
        _expect_code(caught, EvidenceErrorCode.EVIDENCE_RUN_MISMATCH)
    assert target.items == ()


def test_cross_run_parent_record_and_link_cannot_enter_target() -> None:
    source = EvidenceLedgerBuilder("RUN-AAAAAAAAAAAA")
    parent = _append_new(source, statement="Source parent aggregate.")
    _append_new(
        source,
        component="RIEC",
        statement="Source child aggregate.",
        parent_evidence_ids=[parent.item.evidence_id],
    )
    foreign_ledger = source.finalize()
    foreign_records = _bind_items(
        foreign_ledger,
        expected_source_run_id="RUN-AAAAAAAAAAAA",
    )
    target = EvidenceLedgerBuilder("RUN-BBBBBBBBBBBB")
    for foreign in foreign_records:
        with pytest.raises(EvidenceError) as caught:
            target.append(foreign)
        _expect_code(caught, EvidenceErrorCode.EVIDENCE_RUN_MISMATCH)
    _append_new(
        target,
        component="ACTION",
        kind="decision_reason",
        status="warning",
        statement="Target child cannot claim a foreign parent.",
        parent_evidence_ids=[parent.item.evidence_id],
    )
    with pytest.raises(EvidenceError) as caught_parent:
        target.finalize()
    _expect_code(caught_parent, EvidenceErrorCode.EVIDENCE_PARENT_NOT_FOUND)


def test_identical_content_does_not_bypass_run_ownership() -> None:
    source = EvidenceLedgerBuilder("RUN-AAAAAAAAAAAA")
    source_item = _append_new(source)
    foreign_ledger = source.finalize()
    foreign = _bind_items(
        foreign_ledger,
        expected_source_run_id="RUN-AAAAAAAAAAAA",
    )[0]
    target = EvidenceLedgerBuilder("RUN-BBBBBBBBBBBB")
    target_item = _append_new(target)
    assert source_item.item.evidence_id == target_item.item.evidence_id
    assert source_item.item.content_sha256 == target_item.item.content_sha256
    with pytest.raises(EvidenceError) as caught:
        target.append(foreign)
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_RUN_MISMATCH)
    assert target.items == (target_item.item,)


def test_expected_run_verification_without_ownership_context_fails_closed() -> None:
    builder = EvidenceLedgerBuilder(RUN_ID)
    _append_new(builder)
    ledger = builder.finalize()
    with pytest.raises(EvidenceError) as caught:
        verify_ledger(ledger, expected_run_id=RUN_ID)
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_RUN_MISMATCH)


def test_invalid_implementation_version_is_rejected() -> None:
    with pytest.raises(EvidenceError) as caught:
        _item(implementation_version="version with spaces")
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT)


def test_secret_like_implementation_version_is_rejected() -> None:
    with pytest.raises(EvidenceError) as caught:
        _item(implementation_version="sk-" + "A" * 20)
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT)


def test_secret_like_source_artifact_identity_is_rejected() -> None:
    with pytest.raises(EvidenceError) as caught:
        _item(
            source_refs=[
                {
                    "artifact_id": "ghp_" + "a" * 20,
                    "artifact_sha256": SOURCE_HASH,
                    "locator": "public fixture",
                }
            ]
        )
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_SOURCE_REF_INVALID)


def test_unencodable_evidence_value_has_stable_typed_failure() -> None:
    with pytest.raises(EvidenceError) as caught:
        _item(value={"note": "\ud800"})
    _expect_code(caught, EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT)


def test_sha256_file_rejects_symbolic_link(tmp_path: Path) -> None:
    target = tmp_path / "target.bin"
    target.write_bytes(b"safe")
    link = tmp_path / "link.bin"
    link.symlink_to(target)
    with pytest.raises(CanonicalJsonError):
        sha256_file(link)


def test_evidence_identity_excludes_exactly_three_fields() -> None:
    item = _item()
    payload = item.to_canonical_dict()
    for excluded in ("evidence_id", "created_at", "content_sha256"):
        assert excluded in payload
    identity = evidence_identity(item)
    assert identity.content_sha256 == item.content_sha256
