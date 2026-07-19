from __future__ import annotations

import inspect
import json
import os
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from riec_guard.contract import schema_loader
from riec_guard.contract.schema_loader import (
    SchemaKind,
    SchemaRegistry,
    SchemaRegistryError,
    load_schema_registry,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PRODUCTION_SCHEMAS = PROJECT_ROOT / "schemas"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _fixture_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    repository = tmp_path / "synthetic-repository"
    shutil.copytree(PRODUCTION_SCHEMAS, repository / "schemas")
    monkeypatch.setattr(schema_loader, "_REPOSITORY_ROOT", repository)
    return repository


def _index(repository: Path) -> dict[str, Any]:
    return _load_json(repository / "schemas" / "SCHEMA_INDEX.json")


def _write_index(repository: Path, index: dict[str, Any]) -> None:
    _write_json(repository / "schemas" / "SCHEMA_INDEX.json", index)


def _entry(index: dict[str, Any], logical_name: str) -> dict[str, Any]:
    return next(item for item in index["entries"] if item["logical_name"] == logical_name)


def _mutate_index(repository: Path, mutation: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    index = _index(repository)
    mutation(index)
    _write_index(repository, index)
    return index


def _assert_error(code: str) -> SchemaRegistryError:
    with pytest.raises(SchemaRegistryError) as exc_info:
        load_schema_registry()
    assert exc_info.value.code == code
    return exc_info.value


def test_production_index_resolves_exactly_11_canonical_schemas():
    registry = load_schema_registry()
    assert len(registry.canonical()) == 11
    assert all(record.kind is SchemaKind.CANONICAL for record in registry.canonical())


def test_production_index_resolves_exactly_3_gpt_projections():
    registry = load_schema_registry()
    assert len(registry.gpt_projections()) == 3
    assert all(record.kind is SchemaKind.GPT_PROJECTION for record in registry.gpt_projections())


def test_every_production_example_validates_when_registry_loads():
    registry = load_schema_registry()
    assert len(registry.canonical()) + len(registry.gpt_projections()) == 14
    assert all(record.example() for record in (*registry.canonical(), *registry.gpt_projections()))


def test_canonical_lookup_by_logical_name_works():
    record = load_schema_registry().lookup("audit_contract")
    assert record.kind is SchemaKind.CANONICAL
    assert record.schema()["title"] == "RIEC Guard AuditContract"


def test_gpt_projection_lookup_by_logical_name_works():
    record = load_schema_registry().lookup("gpt_audit_contract_draft")
    assert record.kind is SchemaKind.GPT_PROJECTION
    assert record.schema()["name"] == "riec_guard_contract_draft"


def test_gpt_promotion_targets_resolve_to_canonical_schemas():
    registry = load_schema_registry()
    mappings = {
        record.logical_name: registry.promotion_target(record.logical_name).logical_name
        for record in registry.gpt_projections()
    }
    assert mappings == {
        "gpt_audit_contract_draft": "audit_contract",
        "gpt_claim_audit": "claim_audit",
        "gpt_report_draft": "report_draft",
    }
    assert all(
        registry.promotion_target(record.logical_name).kind is SchemaKind.CANONICAL
        for record in registry.gpt_projections()
    )


def test_canonical_and_gpt_projection_lists_remain_separate():
    registry = load_schema_registry()
    canonical_names = {record.logical_name for record in registry.canonical()}
    projection_names = {record.logical_name for record in registry.gpt_projections()}
    assert canonical_names.isdisjoint(projection_names)
    assert not any(name.startswith("gpt_") for name in canonical_names)


def test_returned_schemas_and_examples_cannot_mutate_registry_state():
    registry = load_schema_registry()
    record = registry.lookup("audit_contract")
    schema = record.schema()
    example = record.example()
    schema["title"] = "mutated"
    example["schema_version"] = "999.0.0"
    assert registry.lookup("audit_contract").schema()["title"] == "RIEC Guard AuditContract"
    assert registry.lookup("audit_contract").example()["schema_version"] == "1.0.0"


def test_public_loader_accepts_no_caller_provided_path():
    assert list(inspect.signature(load_schema_registry).parameters) == []


def test_missing_schema_file_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = _fixture_repository(tmp_path, monkeypatch)
    index = _index(repository)
    path = repository / _entry(index, "audit_contract")["schema_path"]
    path.unlink()
    _assert_error("SCHEMA_FILE_MISSING")


def test_missing_example_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = _fixture_repository(tmp_path, monkeypatch)
    index = _index(repository)
    path = repository / _entry(index, "audit_contract")["example_path"]
    path.unlink()
    _assert_error("SCHEMA_EXAMPLE_MISSING")


def test_duplicate_logical_name_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = _fixture_repository(tmp_path, monkeypatch)

    def duplicate(index: dict[str, Any]) -> None:
        index["entries"][1]["logical_name"] = index["entries"][0]["logical_name"]

    _mutate_index(repository, duplicate)
    _assert_error("DUPLICATE_LOGICAL_NAME")


def test_duplicate_schema_path_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = _fixture_repository(tmp_path, monkeypatch)

    def duplicate(index: dict[str, Any]) -> None:
        index["entries"][1]["schema_path"] = index["entries"][0]["schema_path"]

    _mutate_index(repository, duplicate)
    _assert_error("DUPLICATE_SCHEMA_PATH")


def test_duplicate_canonical_id_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = _fixture_repository(tmp_path, monkeypatch)
    index = _index(repository)
    first_path = repository / _entry(index, "action_decision")["schema_path"]
    second_path = repository / _entry(index, "audit_contract")["schema_path"]
    first = _load_json(first_path)
    second = _load_json(second_path)
    second["$id"] = first["$id"]
    _write_json(second_path, second)
    _assert_error("DUPLICATE_SCHEMA_ID")


def test_unsupported_index_version_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = _fixture_repository(tmp_path, monkeypatch)
    _mutate_index(repository, lambda index: index.update(index_version="999.0.0"))
    _assert_error("INDEX_VERSION_UNSUPPORTED")


def test_unknown_schema_kind_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = _fixture_repository(tmp_path, monkeypatch)
    _mutate_index(repository, lambda index: index["entries"][0].update(kind="unknown_kind"))
    _assert_error("SCHEMA_KIND_UNKNOWN")


def test_canonical_schema_version_mismatch_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repository = _fixture_repository(tmp_path, monkeypatch)
    _mutate_index(
        repository,
        lambda index: _entry(index, "audit_contract").update(schema_version="2.0.0"),
    )
    _assert_error("CANONICAL_VERSION_MISMATCH")


def test_canonical_example_version_mismatch_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repository = _fixture_repository(tmp_path, monkeypatch)
    index = _index(repository)
    example_path = repository / _entry(index, "audit_contract")["example_path"]
    example = _load_json(example_path)
    example["schema_version"] = "2.0.0"
    _write_json(example_path, example)
    _assert_error("CANONICAL_EXAMPLE_VERSION_MISMATCH")


def test_missing_gpt_promotion_target_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = _fixture_repository(tmp_path, monkeypatch)

    def remove_target(index: dict[str, Any]) -> None:
        _entry(index, "gpt_audit_contract_draft").pop("promotes_to")

    _mutate_index(repository, remove_target)
    _assert_error("GPT_PROMOTION_MISSING")


def test_unknown_gpt_promotion_target_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = _fixture_repository(tmp_path, monkeypatch)
    _mutate_index(
        repository,
        lambda index: _entry(index, "gpt_audit_contract_draft").update(
            promotes_to="missing_canonical"
        ),
    )
    _assert_error("GPT_PROMOTION_TARGET_INVALID")


def test_gpt_projection_cannot_promote_to_another_gpt_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repository = _fixture_repository(tmp_path, monkeypatch)
    _mutate_index(
        repository,
        lambda index: _entry(index, "gpt_audit_contract_draft").update(
            promotes_to="gpt_report_draft"
        ),
    )
    _assert_error("GPT_PROMOTION_TARGET_INVALID")


def test_absolute_path_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = _fixture_repository(tmp_path, monkeypatch)
    absolute = "/" + "tmp" + "/outside-schema.json"
    _mutate_index(
        repository,
        lambda index: _entry(index, "audit_contract").update(schema_path=absolute),
    )
    _assert_error("INDEX_PATH_INVALID")


def test_posix_traversal_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = _fixture_repository(tmp_path, monkeypatch)
    traversal = "schemas/canonical/" + "../" * 2 + "outside-schema.json"
    _mutate_index(
        repository,
        lambda index: _entry(index, "audit_contract").update(schema_path=traversal),
    )
    _assert_error("INDEX_PATH_INVALID")


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "schemas" + "\\" + "canonical" + "\\..\\outside-schema.json",
        "C" + ":" + "\\" + "outside-schema.json",
    ],
)
def test_windows_traversal_and_drive_paths_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unsafe_path: str
):
    repository = _fixture_repository(tmp_path, monkeypatch)
    _mutate_index(
        repository,
        lambda index: _entry(index, "audit_contract").update(schema_path=unsafe_path),
    )
    _assert_error("INDEX_PATH_INVALID")


@pytest.mark.skipif(os.name == "nt", reason="symlink fixture requires POSIX behavior")
def test_symlink_path_resolution_escape_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repository = _fixture_repository(tmp_path, monkeypatch)
    index = _index(repository)
    schema_path = repository / _entry(index, "audit_contract")["schema_path"]
    outside = tmp_path / "outside-schema.json"
    shutil.copyfile(schema_path, outside)
    schema_path.unlink()
    schema_path.symlink_to(outside)
    _assert_error("INDEX_PATH_ESCAPE")


def test_invalid_canonical_schema_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = _fixture_repository(tmp_path, monkeypatch)
    index = _index(repository)
    schema_path = repository / _entry(index, "audit_contract")["schema_path"]
    schema = _load_json(schema_path)
    schema["type"] = "not-a-json-schema-type"
    _write_json(schema_path, schema)
    _assert_error("SCHEMA_DEFINITION_INVALID")


def test_invalid_canonical_example_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = _fixture_repository(tmp_path, monkeypatch)
    index = _index(repository)
    example_path = repository / _entry(index, "audit_contract")["example_path"]
    example = _load_json(example_path)
    example["unexpected_field"] = True
    _write_json(example_path, example)
    _assert_error("SCHEMA_EXAMPLE_INVALID")


def test_invalid_gpt_inner_schema_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = _fixture_repository(tmp_path, monkeypatch)
    index = _index(repository)
    schema_path = repository / _entry(index, "gpt_report_draft")["schema_path"]
    wrapper = _load_json(schema_path)
    wrapper["schema"]["type"] = "not-a-json-schema-type"
    _write_json(schema_path, wrapper)
    _assert_error("SCHEMA_DEFINITION_INVALID")


def test_invalid_gpt_example_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = _fixture_repository(tmp_path, monkeypatch)
    index = _index(repository)
    example_path = repository / _entry(index, "gpt_report_draft")["example_path"]
    example = _load_json(example_path)
    example["unexpected_field"] = True
    _write_json(example_path, example)
    _assert_error("SCHEMA_EXAMPLE_INVALID")


def test_non_local_json_schema_reference_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repository = _fixture_repository(tmp_path, monkeypatch)
    index = _index(repository)
    schema_path = repository / _entry(index, "audit_contract")["schema_path"]
    schema = _load_json(schema_path)
    schema["properties"]["source"] = {"$ref": "https://example.invalid/schema.json"}
    _write_json(schema_path, schema)
    _assert_error("REMOTE_REF_FORBIDDEN")


def test_public_exceptions_do_not_reveal_absolute_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repository = _fixture_repository(tmp_path, monkeypatch)
    index = _index(repository)
    path = repository / _entry(index, "audit_contract")["schema_path"]
    path.unlink()
    error = _assert_error("SCHEMA_FILE_MISSING")
    assert str(repository.resolve()) not in str(error)
    assert not str(error).startswith("/")


def test_validation_order_and_diagnostics_are_deterministic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repository = _fixture_repository(tmp_path, monkeypatch)

    def duplicate(index: dict[str, Any]) -> None:
        index["entries"][1]["logical_name"] = index["entries"][0]["logical_name"]
        index["entries"][1]["schema_path"] = index["entries"][0]["schema_path"]

    _mutate_index(repository, duplicate)
    observed: list[tuple[str, str]] = []
    for _ in range(2):
        with pytest.raises(SchemaRegistryError) as exc_info:
            load_schema_registry()
        observed.append((exc_info.value.code, str(exc_info.value)))
    assert observed[0] == observed[1]
    assert observed[0][0] == "DUPLICATE_LOGICAL_NAME"


def test_registry_index_version_is_exposed() -> None:
    registry: SchemaRegistry = load_schema_registry()
    assert registry.index_version == "1.0.0"
