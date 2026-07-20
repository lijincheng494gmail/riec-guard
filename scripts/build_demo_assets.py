"""Build or quickly verify the fixed public Macro-03 demonstration assets."""

from __future__ import annotations

import argparse
import csv
import io
import math
import os
import re
import stat
import sys
import tempfile
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from riec_guard.benchmarks.catalog import (  # noqa: E402
    build_scenario_catalog,
    json_asset_bytes,
    parse_json_object,
    seal_benchmark_summary,
    validate_benchmark_identity,
)
from riec_guard.benchmarks.models import (  # noqa: E402
    DemoBenchmarkSummary,
    DemoScenarioResult,
    RecordedScenarioSummary,
    SCENARIO_ORDER,
    ScenarioCatalog,
    ScenarioDefinition,
    ScenarioId,
)
from riec_guard.benchmarks.scenarios import (  # noqa: E402
    generate_scenario,
    scenario_definitions,
    shared_policy,
)
from riec_guard.contract.models import ProtocolId  # noqa: E402

_CATALOG_ASSET = "demo_assets/scenario_catalog.v1.json"
_SUMMARY_ASSET = "demo_assets/benchmark_summary.v1.json"
_CSV_ASSETS = (
    "data/public_synthetic/stable_symmetric.csv",
    "data/public_synthetic/heavy_tail_particulate.csv",
    "data/public_synthetic/batch_drift_change_point.csv",
)
_ALLOWED_ASSETS = frozenset((*_CSV_ASSETS, _CATALOG_ASSET, _SUMMARY_ASSET))
_HEADER = (
    "quantity",
    "product",
    "batch_id",
    "timestamp",
    "stream",
    "shift",
    "row_sequence",
)
_EXPECTED_PRODUCTS = frozenset({"product_A", "product_B"})
_EXPECTED_STREAMS = frozenset({"stream_1", "stream_2"})
_EXPECTED_SHIFTS = frozenset({"day", "night"})
_SHA256_PATTERN = re.compile(r"[a-f0-9]{64}\Z")
_QUANTITY_PATTERN = re.compile(r"-?[0-9]+\.[0-9]{2}\Z")
_TIMESTAMP_PATTERN = re.compile(r"2026-07-(?:18|19)T[0-9]{2}:[0-9]{2}:00Z\Z")
_UNSAFE_CONTENT_PATTERNS = (
    re.compile(r"(?i)\bprivate\b"),
    re.compile(r"(?i)private[_ -]?(?:local|dairy|root|reference)"),
    re.compile(r"(?i)(?:publisher|reviewer|manuscript|historical[_ -]?archive)"),
    re.compile(r"(?<![A-Za-z0-9])/(?:Users|home|private|tmp|var/tmp|var/folders)/[^\s\"'<>]+"),
    re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:\\[^\s\"'<>]+"),
    re.compile(r"\\\\[A-Za-z0-9._$-]+\\[A-Za-z0-9._$-]+"),
    re.compile(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    re.compile(r"-----BEGIN[ ](?:RSA[ ]|EC[ ]|OPENSSH[ ]|DSA[ ]|PGP[ ])?PRIVATE[ ]KEY-----"),
    re.compile(r"(?i)\bBearer[ \t]+[A-Za-z0-9._~-]{16,}"),
    re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
)
_MAX_ASSET_BYTES = 10 * 1024 * 1024


class DemoAssetError(ValueError):
    """Safe bounded failure for a fixed public asset operation."""


def write_assets() -> None:
    """Run each real service once, then atomically write the five fixed assets."""

    # These imports deliberately remain inside the analytical write path.  The fast
    # check path must neither import nor invoke the runner or AuditService.
    from riec_guard.benchmarks.runner import run_public_demo_scenario
    from riec_guard.domain.source import SourceRepository
    from riec_guard.errors import ErrorEnvelope
    from riec_guard.settings import RuntimeSettings

    definitions = _definitions()
    generated = tuple(generate_scenario(definition.scenario_id) for definition in definitions)
    catalog = build_scenario_catalog()
    records: list[RecordedScenarioSummary] = []

    with tempfile.TemporaryDirectory(prefix="riec-guard-macro03-") as temporary:
        temporary_root = Path(temporary).resolve(strict=True)
        if temporary_root == PROJECT_ROOT or temporary_root.is_relative_to(PROJECT_ROOT):
            raise DemoAssetError("temporary run root must remain outside the repository")
        repository = SourceRepository(RuntimeSettings(ephemeral_root=temporary_root / "runs"))
        for definition, source in zip(definitions, generated, strict=True):
            result = run_public_demo_scenario(
                repository,
                scenario_id=definition.scenario_id.value,
            )
            if isinstance(result, ErrorEnvelope):
                raise DemoAssetError(f"recorded scenario analysis failed [{result.code}]")
            if not isinstance(result, DemoScenarioResult):
                raise DemoAssetError("recorded scenario analysis returned an invalid result")
            _validate_live_result(
                result, definition=definition, dataset_sha256=source.dataset_sha256
            )
            records.append(result.summary)

    summary = seal_benchmark_summary(
        tuple(records),
        catalog_sha256=catalog.content_sha256,
    )
    _validate_recorded_summary(
        summary,
        catalog=catalog,
        generated_sha256={item.definition.scenario_id: item.dataset_sha256 for item in generated},
    )
    payloads: dict[str, bytes] = {item.definition.csv_asset: item.csv_bytes for item in generated}
    payloads[_CATALOG_ASSET] = json_asset_bytes(catalog)
    payloads[_SUMMARY_ASSET] = json_asset_bytes(summary)
    _validate_fixed_payloads(payloads)
    _write_fixed_payloads(payloads)


def check_assets() -> None:
    """Verify committed bytes and recorded identities without running analysis."""

    definitions = _definitions()
    generated = tuple(generate_scenario(definition.scenario_id) for definition in definitions)
    expected_catalog = build_scenario_catalog()

    for source in generated:
        committed = _read_fixed_asset(source.definition.csv_asset)
        if committed != source.csv_bytes:
            raise DemoAssetError("committed scenario CSV does not match its generator")
        _validate_csv(committed)

    catalog_bytes = _read_fixed_asset(_CATALOG_ASSET)
    try:
        catalog = ScenarioCatalog.model_validate(parse_json_object(catalog_bytes))
    except (TypeError, ValueError):
        raise DemoAssetError("committed scenario catalog is invalid") from None
    if catalog.to_canonical_dict() != expected_catalog.to_canonical_dict():
        raise DemoAssetError("committed scenario catalog does not match the fixed registry")
    if catalog_bytes != json_asset_bytes(expected_catalog):
        raise DemoAssetError("committed scenario catalog bytes are not canonical")

    summary_bytes = _read_fixed_asset(_SUMMARY_ASSET)
    try:
        summary = DemoBenchmarkSummary.model_validate(parse_json_object(summary_bytes))
    except (TypeError, ValueError):
        raise DemoAssetError("committed benchmark summary is invalid") from None
    _validate_recorded_summary(
        summary,
        catalog=catalog,
        generated_sha256={item.definition.scenario_id: item.dataset_sha256 for item in generated},
    )
    expected_summary = seal_benchmark_summary(
        tuple(summary.scenarios),
        catalog_sha256=catalog.content_sha256,
    )
    if summary.to_canonical_dict() != expected_summary.to_canonical_dict():
        raise DemoAssetError("committed benchmark summary metadata is invalid")
    if summary_bytes != json_asset_bytes(summary):
        raise DemoAssetError("committed benchmark summary bytes are not canonical")

    checked = {source.definition.csv_asset: source.csv_bytes for source in generated}
    checked[_CATALOG_ASSET] = catalog_bytes
    checked[_SUMMARY_ASSET] = summary_bytes
    _validate_fixed_payloads(checked)


def _definitions() -> tuple[ScenarioDefinition, ...]:
    definitions = scenario_definitions()
    if (
        len(definitions) != 3
        or tuple(definition.scenario_id for definition in definitions) != SCENARIO_ORDER
        or tuple(definition.csv_asset for definition in definitions) != _CSV_ASSETS
    ):
        raise DemoAssetError("public scenario registry is not the fixed three-world registry")
    return definitions


def _validate_live_result(
    result: DemoScenarioResult,
    *,
    definition: ScenarioDefinition,
    dataset_sha256: str,
) -> None:
    if result.definition != definition or result.summary.scenario_id is not definition.scenario_id:
        raise DemoAssetError("recorded scenario identity does not match its definition")
    if result.summary.dataset_sha256 != dataset_sha256:
        raise DemoAssetError("recorded dataset identity does not match generated bytes")
    if result.action.state is not definition.expectation.action_state:
        raise DemoAssetError("ordinary service action does not match the scenario expectation")
    if result.summary.action_state is not result.action.state:
        raise DemoAssetError("display action does not match the canonical action artifact")
    if result.summary.protocol_conflict != definition.expectation.protocol_conflict:
        raise DemoAssetError("ordinary service conflict state does not match the expectation")
    if result.summary.g1_state is not definition.expectation.g1_state:
        raise DemoAssetError("ordinary service stability state does not match the expectation")
    if result.summary.g2.action_supported is not True:
        raise DemoAssetError("ordinary service did not establish full G2 action support")
    if len(result.evidence_ledger.items) != 3:
        raise DemoAssetError("recorded evidence ledger is not the aggregate three-item DAG")
    _validate_record(result.summary, definition=definition, dataset_sha256=dataset_sha256)


def _validate_recorded_summary(
    summary: DemoBenchmarkSummary,
    *,
    catalog: ScenarioCatalog,
    generated_sha256: Mapping[ScenarioId, str],
) -> None:
    try:
        validate_benchmark_identity(summary, catalog=catalog)
    except (TypeError, ValueError):
        raise DemoAssetError("benchmark summary identity is invalid") from None
    if summary.schema_version != "1.0.0" or len(summary.scenarios) != 3:
        raise DemoAssetError("benchmark summary version or scenario count is invalid")
    if summary.bootstrap_replicates != 200 or summary.bootstrap_seed != 20260718:
        raise DemoAssetError("benchmark summary does not record production bootstrap defaults")
    summary_payload = summary.to_canonical_dict()
    if summary_payload.get("shared_policy") != shared_policy().to_canonical_dict():
        raise DemoAssetError("benchmark summary does not bind the frozen shared policy")
    definitions = _definitions()
    for definition, record in zip(definitions, summary.scenarios, strict=True):
        expected_sha256 = generated_sha256.get(definition.scenario_id)
        if not isinstance(expected_sha256, str):
            raise DemoAssetError("generated scenario identity is unavailable")
        _validate_record(record, definition=definition, dataset_sha256=expected_sha256)


def _validate_record(
    record: RecordedScenarioSummary,
    *,
    definition: ScenarioDefinition,
    dataset_sha256: str,
) -> None:
    if record.scenario_id is not definition.scenario_id or record.scenario_version != "1.0.0":
        raise DemoAssetError("recorded scenario version or order is invalid")
    if record.dataset_sha256 != dataset_sha256 or _SHA256_PATTERN.fullmatch(dataset_sha256) is None:
        raise DemoAssetError("recorded scenario dataset hash is invalid")
    if (
        record.row_count != 1056
        or record.deployment_group_count != 12
        or record.product_count != 2
        or record.rows_per_product != 528
        or record.expected_tail_count_per_product != 5.28
    ):
        raise DemoAssetError("recorded scenario design counts are invalid")
    if record.policy_profile_id != definition.policy.profile_id:
        raise DemoAssetError("recorded scenario policy identity is invalid")
    if record.action_state is not definition.expectation.action_state:
        raise DemoAssetError("recorded action does not match the qualitative expectation")
    if record.protocol_conflict != definition.expectation.protocol_conflict:
        raise DemoAssetError("recorded conflict state does not match the qualitative expectation")
    if record.g1_state is not definition.expectation.g1_state:
        raise DemoAssetError("recorded G1 state does not match the qualitative expectation")
    if (
        record.g2.action_supported is not True
        or record.g2.minimum_product_rows != 528
        or record.g2.minimum_product_groups != 12
        or record.g2.alpha != 0.01
        or record.g2.expected_tail_count != 5.28
        or record.g2.min_expected_tail_count != 5.0
    ):
        raise DemoAssetError("recorded G2 evidence arithmetic is invalid")
    if (
        record.u1.requested_replicates != 200
        or record.u1.seed != 20260718
        or record.u1.successful_replicates + record.u1.failed_replicates != 200
    ):
        raise DemoAssetError("recorded bootstrap provenance is invalid")
    if (
        record.h1.protocol_id is not ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE
        or record.h2.protocol_id is not ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL
        or record.h3.protocol_id is not ProtocolId.H3_STUDENT_T_RESIDUAL_TAIL
    ):
        raise DemoAssetError("recorded headroom protocol identities are invalid")

    pilot = (record.pilot_min, record.pilot_max)
    if definition.expectation.positive_pilot_interval:
        if (
            pilot[0] is None
            or pilot[1] is None
            or float(pilot[0]) <= 0.0
            or float(pilot[1]) < float(pilot[0])
        ):
            raise DemoAssetError("recorded pilot interval is not positive and ordered")
    elif pilot != (None, None):
        raise DemoAssetError("recorded non-pilot action unexpectedly contains an interval")

    if definition.expectation.h2_more_optimistic_than_h1_or_h3:
        alternatives = [
            float(value) for value in (record.h1.value, record.h3.value) if value is not None
        ]
        if (
            record.h2.value is None
            or not alternatives
            or float(record.h2.value) <= min(alternatives)
        ):
            raise DemoAssetError("recorded H2 result is not more optimistic than H1 or H3")
        if float(record.h2.value) - min(alternatives) < 0.1:
            raise DemoAssetError("recorded H2 optimism is not materially separated")

    nodes = record.evidence_chain
    if tuple(node.component for node in nodes) != ("RIEC", "PROTOCOL", "ACTION"):
        raise DemoAssetError("recorded evidence components are not in canonical ancestry order")
    riec, protocol, action = nodes
    if (
        riec.evidence_id != record.riec_evidence_id
        or protocol.evidence_id != record.protocol_evidence_id
        or action.evidence_id != record.action_evidence_id
        or riec.parent_evidence_ids != ()
        or protocol.parent_evidence_ids != (riec.evidence_id,)
        or set(action.parent_evidence_ids) != {riec.evidence_id, protocol.evidence_id}
    ):
        raise DemoAssetError("recorded evidence ancestry is invalid")
    if len({node.evidence_id for node in nodes}) != 3:
        raise DemoAssetError("recorded evidence identities are not unique")


def _validate_csv(data: bytes) -> None:
    try:
        text = data.decode("utf-8")
        rows = tuple(csv.reader(io.StringIO(text, newline=""), strict=True))
    except (UnicodeDecodeError, csv.Error):
        raise DemoAssetError("committed scenario CSV is invalid") from None
    if not data.endswith(b"\n") or not rows or tuple(rows[0]) != _HEADER:
        raise DemoAssetError("committed scenario CSV framing is invalid")
    body = rows[1:]
    if len(body) != 1056 or any(len(row) != len(_HEADER) for row in body):
        raise DemoAssetError("committed scenario CSV dimensions are invalid")

    group_counts: Counter[str] = Counter()
    product_counts: Counter[str] = Counter()
    cell_counts: Counter[tuple[str, str, str, str]] = Counter()
    observed_groups: set[str] = set()
    observed_products: set[str] = set()
    observed_streams: set[str] = set()
    observed_shifts: set[str] = set()
    last_timestamp_by_stream: dict[str, str] = {}
    for expected_sequence, row in enumerate(body, start=1):
        quantity, product, group, timestamp, stream, shift, sequence = row
        if _QUANTITY_PATTERN.fullmatch(quantity) is None or not math.isfinite(float(quantity)):
            raise DemoAssetError("committed scenario contains an invalid quantity")
        if sequence != str(expected_sequence):
            raise DemoAssetError("committed scenario row ordering is invalid")
        previous_timestamp = last_timestamp_by_stream.get(stream)
        if (
            _TIMESTAMP_PATTERN.fullmatch(timestamp) is None
            or previous_timestamp is not None
            and timestamp <= previous_timestamp
        ):
            raise DemoAssetError("committed scenario timestamp ordering is invalid")
        last_timestamp_by_stream[stream] = timestamp
        group_counts[group] += 1
        product_counts[product] += 1
        cell_counts[(group, product, stream, shift)] += 1
        observed_groups.add(group)
        observed_products.add(product)
        observed_streams.add(stream)
        observed_shifts.add(shift)
    if (
        observed_groups != {f"batch_{index:02d}" for index in range(1, 13)}
        or observed_products != _EXPECTED_PRODUCTS
        or observed_streams != _EXPECTED_STREAMS
        or observed_shifts != _EXPECTED_SHIFTS
        or set(group_counts.values()) != {88}
        or set(product_counts.values()) != {528}
        or len(cell_counts) != 12 * 2 * 2 * 2
        or set(cell_counts.values()) != {11}
    ):
        raise DemoAssetError("committed scenario balance is invalid")


def _validate_fixed_payloads(payloads: dict[str, bytes]) -> None:
    if set(payloads) != _ALLOWED_ASSETS:
        raise DemoAssetError("asset operation attempted a non-allowlisted target")
    for relative, data in payloads.items():
        if not data or len(data) > _MAX_ASSET_BYTES:
            raise DemoAssetError("public asset is empty or exceeds the release size limit")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise DemoAssetError("public asset is not UTF-8 text") from None
        if "\x00" in text or any(pattern.search(text) for pattern in _UNSAFE_CONTENT_PATTERNS):
            raise DemoAssetError("public asset contains prohibited content")
        if relative.endswith(".csv"):
            _validate_csv(data)


def _fixed_path(relative: str) -> Path:
    if relative not in _ALLOWED_ASSETS:
        raise DemoAssetError("asset path is not allowlisted")
    candidate = PROJECT_ROOT / relative
    if candidate.parent == PROJECT_ROOT or not candidate.parent.is_relative_to(PROJECT_ROOT):
        raise DemoAssetError("asset path is outside the public repository")
    try:
        parent_metadata = candidate.parent.lstat()
        resolved_parent = candidate.parent.resolve(strict=True)
    except OSError:
        raise DemoAssetError("fixed public asset directory is unavailable") from None
    if (
        stat.S_ISLNK(parent_metadata.st_mode)
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or resolved_parent != candidate.parent
        or not resolved_parent.is_relative_to(PROJECT_ROOT)
    ):
        raise DemoAssetError("fixed public asset directory is unsafe")
    return candidate


def _read_fixed_asset(relative: str) -> bytes:
    path = _fixed_path(relative)
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise OSError("unsafe asset type")
        if metadata.st_size > _MAX_ASSET_BYTES:
            raise OSError("asset too large")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                metadata.st_dev,
                metadata.st_ino,
            ):
                raise OSError("asset changed identity")
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                data = handle.read(_MAX_ASSET_BYTES + 1)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    except OSError:
        raise DemoAssetError("required committed public asset is unavailable") from None
    if len(data) > _MAX_ASSET_BYTES:
        raise DemoAssetError("required committed public asset exceeds the size limit")
    return data


def _write_fixed_payloads(payloads: dict[str, bytes]) -> None:
    staged: list[tuple[Path, Path]] = []
    try:
        for relative in sorted(payloads):
            target = _fixed_path(relative)
            descriptor, staged_name = tempfile.mkstemp(
                prefix=f".{target.name}.",
                suffix=".tmp",
                dir=target.parent,
            )
            staged_path = Path(staged_name)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(payloads[relative])
                    handle.flush()
                    os.fsync(handle.fileno())
                staged_path.chmod(0o644)
            except BaseException:
                staged_path.unlink(missing_ok=True)
                raise
            staged.append((staged_path, target))
        for staged_path, target in staged:
            os.replace(staged_path, target)
    except OSError:
        raise DemoAssetError("fixed public assets could not be written safely") from None
    finally:
        for staged_path, _target in staged:
            staged_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build or verify the fixed public RIEC Guard demo assets"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="run and write all recorded assets")
    mode.add_argument("--check", action="store_true", help="verify assets without analysis")
    args = parser.parse_args(argv)
    try:
        if args.write:
            write_assets()
            print("Public demo assets written: 3 scenarios, production bootstrap 200")
        else:
            check_assets()
            print("Public demo asset check passed: 3 scenarios (recorded output, no analysis)")
    except (DemoAssetError, OSError, TypeError, ValueError):
        print("Public demo asset operation failed safely", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
