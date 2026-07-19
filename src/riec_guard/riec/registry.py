from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING, Annotated, Generic, Literal, NoReturn, TypeVar

from pydantic import Field, StringConstraints, ValidationError

from riec_guard.contract.models import CandidateRegistry
from riec_guard.errors import CanonicalModel, ImmutableTuple, StrictStrEnum

if TYPE_CHECKING:
    from riec_guard.decision.claim_boundary import ClaimRuleset
    from riec_guard.protocols.registry import (
        EvidenceProfileConfig,
        PolicyInputRegistry,
        ProtocolRegistry,
    )

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_CONFIG_ROOT = _REPOSITORY_ROOT / "configs"
_MANIFEST_SOURCE_IDENTIFIER = "registry_manifest.v1.json"
_SUPPORTED_VERSION = "1.0.0"
_SAFE_LOGICAL_ID = re.compile(r"[a-z0-9][a-z0-9._-]{2,127}\Z")
_SAFE_SOURCE_ID = re.compile(r"[A-Za-z0-9._/-]{1,240}\Z")

FROZEN_CANDIDATE_IDS = (
    "M0_intercept",
    "M1_product",
    "M2_product_stream",
    "M3_product_shift",
    "M4_product_stream_shift",
    "M5_product_time",
    "M6_product_stream_shift_time",
)
FROZEN_BASELINE_CANDIDATE_ID = "M0_intercept"

_FROZEN_FORMULA_TERMS = {
    "M0_intercept": ("intercept",),
    "M1_product": ("intercept", "product"),
    "M2_product_stream": ("intercept", "product", "stream"),
    "M3_product_shift": ("intercept", "product", "shift"),
    "M4_product_stream_shift": ("intercept", "product", "stream", "shift"),
    "M5_product_time": ("intercept", "product", "time"),
    "M6_product_stream_shift_time": (
        "intercept",
        "product",
        "stream",
        "shift",
        "time",
    ),
}
_FROZEN_REQUIRED_SEMANTICS = {
    candidate_id: (
        "quantity",
        *(term for term in terms if term != "intercept"),
        "deployment_group",
    )
    for candidate_id, terms in _FROZEN_FORMULA_TERMS.items()
}
_KNOWN_NONCANDIDATE_IDS = frozenset(
    {
        "D0_mean_diagnostic",
        "H1_empirical_strict_tail",
        "H2_gaussian_residual_tail",
        "H3_student_t_residual_tail",
        "U1_whole_group_bootstrap",
        "G1_ordered_stability_screen",
        "G2_evidence_sufficiency_gate",
        "nominal_quantity",
        "lower_limit",
        "alpha",
        "measurement_resolution",
        "minimum_actionable_shift",
        "maximum_screening_shift",
        "protocol_spread_tolerance",
        "quantity_unit",
        "quantity_semantics",
        "conversion_method",
    }
)


class RegistryConfigType(StrictStrEnum):
    PREDICTIVE_CANDIDATE = "predictive_candidate"
    DIAGNOSTIC = "diagnostic"
    HEADROOM_PROTOCOL = "headroom_protocol"
    UNCERTAINTY_PROCEDURE = "uncertainty_procedure"
    STABILITY_GATE = "stability_gate"
    SUFFICIENCY_GATE = "sufficiency_gate"
    POLICY_INPUT = "policy_input"
    EVIDENCE_PROFILE = "evidence_profile"
    CLAIM_RULE = "claim_rule"
    CANDIDATE_REGISTRY = "candidate_registry"
    PROTOCOL_REGISTRY = "protocol_registry"
    POLICY_REGISTRY = "policy_registry"
    CLAIM_RULESET = "claim_ruleset"


class RegistryErrorCode(StrictStrEnum):
    REGISTRY_CONFIG_NOT_FOUND = "REGISTRY_CONFIG_NOT_FOUND"
    REGISTRY_CONFIG_INVALID = "REGISTRY_CONFIG_INVALID"
    REGISTRY_MANIFEST_INVALID = "REGISTRY_MANIFEST_INVALID"
    REGISTRY_VERSION_UNSUPPORTED = "REGISTRY_VERSION_UNSUPPORTED"
    REGISTRY_PATH_UNSAFE = "REGISTRY_PATH_UNSAFE"
    REGISTRY_DUPLICATE_ID = "REGISTRY_DUPLICATE_ID"
    REGISTRY_DUPLICATE_PATH = "REGISTRY_DUPLICATE_PATH"
    REGISTRY_DUPLICATE_TYPE_VERSION = "REGISTRY_DUPLICATE_TYPE_VERSION"
    REGISTRY_INTERNAL_ID_MISMATCH = "REGISTRY_INTERNAL_ID_MISMATCH"
    REGISTRY_INTERNAL_VERSION_MISMATCH = "REGISTRY_INTERNAL_VERSION_MISMATCH"
    REGISTRY_NOT_FROZEN = "REGISTRY_NOT_FROZEN"
    REGISTRY_FROZEN_SET_MISMATCH = "REGISTRY_FROZEN_SET_MISMATCH"
    REGISTRY_BASELINE_INVALID = "REGISTRY_BASELINE_INVALID"
    REGISTRY_CATEGORY_INVALID = "REGISTRY_CATEGORY_INVALID"
    REGISTRY_CROSS_TYPE_INSERTION = "REGISTRY_CROSS_TYPE_INSERTION"
    REGISTRY_HASH_MISMATCH = "REGISTRY_HASH_MISMATCH"
    REGISTRY_SYMLINK_ESCAPE = "REGISTRY_SYMLINK_ESCAPE"


class RegistryConfigError(ValueError):
    """Safe deterministic registry failure that never includes a host path or payload."""

    def __init__(
        self,
        code: RegistryErrorCode,
        message: str,
        *,
        logical_id: str | None = None,
    ) -> None:
        super().__init__(message[:500])
        self.code = code
        self.logical_id = (
            logical_id
            if logical_id is not None and _SAFE_LOGICAL_ID.fullmatch(logical_id)
            else None
        )


class ManifestEntry(CanonicalModel):
    logical_id: Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")]
    config_type: RegistryConfigType
    version: Annotated[str, StringConstraints(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]
    repository_relative_path: Annotated[str, StringConstraints(min_length=1, max_length=240)]


class RegistryManifest(CanonicalModel):
    schema_version: Literal["1.0.0"]
    manifest_id: Literal["fill-registry-manifest.v1"]
    manifest_version: Literal["1.0.0"]
    frozen_before_load: Literal[True]
    entries: Annotated[ImmutableTuple[ManifestEntry], Field(min_length=5, max_length=5)]


SnapshotPayloadT = TypeVar("SnapshotPayloadT", bound=CanonicalModel, covariant=True)


@dataclass(frozen=True, slots=True)
class ConfigSnapshot(Generic[SnapshotPayloadT]):
    logical_id: str
    config_type: RegistryConfigType
    version: str
    repository_relative_source: str
    file_sha256: str
    canonical_json_sha256: str
    frozen: bool
    payload: SnapshotPayloadT

    def provenance_record(self) -> dict[str, str | bool]:
        """Return a fresh JSON-safe provenance record without host paths or timestamps."""

        return {
            "logical_id": self.logical_id,
            "config_type": self.config_type.value,
            "version": self.version,
            "repository_relative_source": self.repository_relative_source,
            "file_sha256": self.file_sha256,
            "canonical_json_sha256": self.canonical_json_sha256,
            "frozen": self.frozen,
        }


@dataclass(frozen=True, slots=True)
class RunRegistrySnapshot:
    candidate_registry: ConfigSnapshot[CandidateRegistry]
    protocol_registry: ConfigSnapshot[ProtocolRegistry]
    evidence_profile: ConfigSnapshot[EvidenceProfileConfig]
    policy_registry: ConfigSnapshot[PolicyInputRegistry]
    claim_ruleset: ConfigSnapshot[ClaimRuleset]
    combined_canonical_sha256: str

    def provenance_records(self) -> tuple[dict[str, str | bool], ...]:
        """Return deterministic defensive provenance records in frozen component order."""

        return tuple(
            snapshot.provenance_record()
            for snapshot in (
                self.candidate_registry,
                self.protocol_registry,
                self.evidence_profile,
                self.policy_registry,
                self.claim_ruleset,
            )
        )


class _DuplicateJsonKeyError(ValueError):
    pass


def load_registry_manifest() -> RegistryManifest:
    """Load the one fixed repository-local allowlist manifest."""

    raw_bytes = _read_repository_config(_MANIFEST_SOURCE_IDENTIFIER)
    payload = _parse_json_object(raw_bytes, manifest=True)
    return _validate_manifest_payload(payload)


def load_candidate_registry(
    registry_id: str = "fill-structural-candidates.v1",
    version: str = "1.0.0",
) -> ConfigSnapshot[CandidateRegistry]:
    """Load the frozen canonical M0-M6 predictive candidate registry."""

    return _load_typed_snapshot(
        logical_id=registry_id,
        config_type=RegistryConfigType.CANDIDATE_REGISTRY,
        version=version,
        parser=_parse_candidate_registry,
        internal_id_field="registry_id",
        internal_version_field="registry_version",
        frozen_field="frozen_before_ranking",
    )


def load_run_registry_snapshot() -> RunRegistrySnapshot:
    """Load all allowlisted decision-critical configs and bind one immutable run snapshot."""

    from riec_guard.decision.claim_boundary import load_claim_ruleset
    from riec_guard.protocols.registry import (
        load_evidence_profile,
        load_policy_input_registry,
        load_protocol_registry,
    )

    candidate = load_candidate_registry()
    protocol = load_protocol_registry()
    evidence = load_evidence_profile()
    policy = load_policy_input_registry()
    claims = load_claim_ruleset()
    candidate_ids = {item.candidate_id for item in candidate.payload.candidates}
    protocol_ids = {item.object_id for item in protocol.payload.entries}
    if candidate_ids & protocol_ids:
        _raise(
            RegistryErrorCode.REGISTRY_CROSS_TYPE_INSERTION,
            "Candidate and protocol registries contain a shared stable object ID.",
        )
    snapshots: tuple[ConfigSnapshot[CanonicalModel], ...] = (
        candidate,
        protocol,
        evidence,
        policy,
        claims,
    )
    if any(not snapshot.frozen for snapshot in snapshots):
        _raise(
            RegistryErrorCode.REGISTRY_NOT_FROZEN,
            "Every configuration must be frozen before a run snapshot is created.",
        )
    combined_payload = {
        "configs": [
            {
                "logical_id": snapshot.logical_id,
                "config_type": snapshot.config_type.value,
                "version": snapshot.version,
                "canonical_json_sha256": snapshot.canonical_json_sha256,
            }
            for snapshot in snapshots
        ]
    }
    combined_hash = _sha256(_canonical_json_bytes(combined_payload))
    return RunRegistrySnapshot(
        candidate_registry=candidate,
        protocol_registry=protocol,
        evidence_profile=evidence,
        policy_registry=policy,
        claim_ruleset=claims,
        combined_canonical_sha256=combined_hash,
    )


def verify_config_snapshot_hashes(
    snapshot: ConfigSnapshot[CanonicalModel],
    *,
    expected_file_sha256: str | None = None,
    expected_canonical_json_sha256: str | None = None,
) -> None:
    """Fail safely when caller-supplied provenance hashes do not match a snapshot."""

    if (
        expected_file_sha256 is not None
        and snapshot.file_sha256 != expected_file_sha256
        or expected_canonical_json_sha256 is not None
        and snapshot.canonical_json_sha256 != expected_canonical_json_sha256
    ):
        _raise(
            RegistryErrorCode.REGISTRY_HASH_MISMATCH,
            "A supplied registry provenance hash does not match the immutable snapshot.",
            logical_id=snapshot.logical_id,
        )


def _load_typed_snapshot(
    *,
    logical_id: str,
    config_type: RegistryConfigType,
    version: str,
    parser: Callable[[dict[str, object]], SnapshotPayloadT],
    internal_id_field: str,
    internal_version_field: str,
    frozen_field: str,
) -> ConfigSnapshot[SnapshotPayloadT]:
    entry = _manifest_entry(logical_id, config_type, version)
    raw_bytes = _read_repository_config(entry.repository_relative_path)
    raw_payload = _parse_json_object(raw_bytes, manifest=False)
    payload = parser(raw_payload)
    actual_id = getattr(payload, internal_id_field, None)
    actual_version = getattr(payload, internal_version_field, None)
    if actual_id != entry.logical_id:
        _raise(
            RegistryErrorCode.REGISTRY_INTERNAL_ID_MISMATCH,
            "Configuration internal identity does not match its manifest entry.",
            logical_id=entry.logical_id,
        )
    if actual_version != entry.version:
        _raise(
            RegistryErrorCode.REGISTRY_INTERNAL_VERSION_MISMATCH,
            "Configuration internal version does not match its manifest entry.",
            logical_id=entry.logical_id,
        )
    if getattr(payload, frozen_field, None) is not True:
        _raise(
            RegistryErrorCode.REGISTRY_NOT_FROZEN,
            "Configuration is not frozen at the required execution boundary.",
            logical_id=entry.logical_id,
        )
    canonical_bytes = _canonical_json_bytes(payload.to_canonical_dict())
    return ConfigSnapshot(
        logical_id=entry.logical_id,
        config_type=entry.config_type,
        version=entry.version,
        repository_relative_source=entry.repository_relative_path,
        file_sha256=_sha256(raw_bytes),
        canonical_json_sha256=_sha256(canonical_bytes),
        frozen=True,
        payload=payload,
    )


def _manifest_entry(
    logical_id: str,
    config_type: RegistryConfigType,
    version: str,
) -> ManifestEntry:
    manifest = load_registry_manifest()
    logical_matches = tuple(entry for entry in manifest.entries if entry.logical_id == logical_id)
    if not logical_matches:
        _raise(
            RegistryErrorCode.REGISTRY_CONFIG_NOT_FOUND,
            "Requested logical configuration is not allowlisted.",
            logical_id=logical_id,
        )
    entry = logical_matches[0]
    if entry.version != version:
        _raise(
            RegistryErrorCode.REGISTRY_VERSION_UNSUPPORTED,
            "Requested configuration version is not supported.",
            logical_id=logical_id,
        )
    if entry.config_type is not config_type:
        _raise(
            RegistryErrorCode.REGISTRY_CATEGORY_INVALID,
            "Requested configuration type does not match its manifest category.",
            logical_id=logical_id,
        )
    return entry


def _validate_manifest_payload(payload: dict[str, object]) -> RegistryManifest:
    if (
        payload.get("schema_version") != _SUPPORTED_VERSION
        or payload.get("manifest_version") != _SUPPORTED_VERSION
    ):
        _raise(
            RegistryErrorCode.REGISTRY_VERSION_UNSUPPORTED,
            "Registry manifest version is unsupported.",
        )
    if payload.get("frozen_before_load") is not True:
        _raise(
            RegistryErrorCode.REGISTRY_NOT_FROZEN,
            "Registry manifest must be frozen before configuration loading.",
        )
    raw_entries = payload.get("entries")
    if not isinstance(raw_entries, list):
        _raise(
            RegistryErrorCode.REGISTRY_MANIFEST_INVALID,
            "Registry manifest entries must be a fixed array.",
        )
    logical_ids: set[str] = set()
    paths: set[str] = set()
    type_versions: set[tuple[str, str]] = set()
    observed_types: list[RegistryConfigType] = []
    for raw_entry in raw_entries:
        if not isinstance(raw_entry, Mapping):
            _raise(
                RegistryErrorCode.REGISTRY_MANIFEST_INVALID,
                "Every manifest entry must be an object.",
            )
        logical_id = raw_entry.get("logical_id")
        path = raw_entry.get("repository_relative_path")
        version = raw_entry.get("version")
        raw_type = raw_entry.get("config_type")
        if not all(isinstance(item, str) for item in (logical_id, path, version, raw_type)):
            _raise(
                RegistryErrorCode.REGISTRY_MANIFEST_INVALID,
                "Manifest identity, path, type, and version must be strings.",
            )
        assert isinstance(logical_id, str)
        assert isinstance(path, str)
        assert isinstance(version, str)
        assert isinstance(raw_type, str)
        try:
            config_type = RegistryConfigType(raw_type)
        except ValueError:
            _raise(
                RegistryErrorCode.REGISTRY_CATEGORY_INVALID,
                "Manifest contains an unknown configuration category.",
            )
        if config_type not in _MANIFEST_CONFIG_TYPES:
            _raise(
                RegistryErrorCode.REGISTRY_CATEGORY_INVALID,
                "Manifest category is not a loadable registry configuration type.",
            )
        _validate_relative_source_identifier(path)
        if logical_id in logical_ids:
            _raise(
                RegistryErrorCode.REGISTRY_DUPLICATE_ID,
                "Manifest logical IDs must be unique.",
            )
        if path in paths:
            _raise(
                RegistryErrorCode.REGISTRY_DUPLICATE_PATH,
                "Manifest source identifiers must be unique.",
            )
        type_version = (config_type.value, version)
        if type_version in type_versions:
            _raise(
                RegistryErrorCode.REGISTRY_DUPLICATE_TYPE_VERSION,
                "Manifest type/version pairs must be unique.",
            )
        logical_ids.add(logical_id)
        paths.add(path)
        type_versions.add(type_version)
        observed_types.append(config_type)
    if tuple(observed_types) != _MANIFEST_CONFIG_TYPES:
        _raise(
            RegistryErrorCode.REGISTRY_MANIFEST_INVALID,
            "Manifest must contain every required configuration type once in frozen order.",
        )
    try:
        return RegistryManifest.model_validate(payload)
    except ValidationError:
        _raise(
            RegistryErrorCode.REGISTRY_MANIFEST_INVALID,
            "Registry manifest does not satisfy its strict typed contract.",
        )


_MANIFEST_CONFIG_TYPES = (
    RegistryConfigType.CANDIDATE_REGISTRY,
    RegistryConfigType.PROTOCOL_REGISTRY,
    RegistryConfigType.EVIDENCE_PROFILE,
    RegistryConfigType.POLICY_REGISTRY,
    RegistryConfigType.CLAIM_RULESET,
)


def _parse_candidate_registry(payload: dict[str, object]) -> CandidateRegistry:
    if payload.get("frozen_before_ranking") is not True:
        _raise(
            RegistryErrorCode.REGISTRY_NOT_FROZEN,
            "Candidate registry must be frozen before ranking.",
        )
    baseline = payload.get("baseline_candidate_id")
    if baseline != FROZEN_BASELINE_CANDIDATE_ID:
        _raise(
            RegistryErrorCode.REGISTRY_BASELINE_INVALID,
            "Candidate baseline must be the frozen M0 intercept candidate.",
        )
    raw_candidates = payload.get("candidates")
    if not isinstance(raw_candidates, list):
        _raise(
            RegistryErrorCode.REGISTRY_CONFIG_INVALID,
            "Candidate registry entries must be an ordered array.",
        )
    candidate_ids: list[str] = []
    for raw_candidate in raw_candidates:
        if not isinstance(raw_candidate, Mapping):
            _raise(
                RegistryErrorCode.REGISTRY_CONFIG_INVALID,
                "Every predictive candidate entry must be an object.",
            )
        raw_category = raw_candidate.get("category")
        candidate_id = raw_candidate.get("candidate_id")
        object_id = raw_candidate.get("object_id")
        if raw_category is not None and raw_category != RegistryConfigType.PREDICTIVE_CANDIDATE:
            _raise(
                RegistryErrorCode.REGISTRY_CROSS_TYPE_INSERTION,
                "A noncandidate object cannot enter the predictive candidate registry.",
            )
        if not isinstance(candidate_id, str):
            if isinstance(object_id, str) or raw_category is not None:
                _raise(
                    RegistryErrorCode.REGISTRY_CROSS_TYPE_INSERTION,
                    "A protocol, gate, claim, or policy object cannot enter candidate ranking.",
                )
            _raise(
                RegistryErrorCode.REGISTRY_CONFIG_INVALID,
                "Every candidate requires a stable candidate ID.",
            )
        if candidate_id in _KNOWN_NONCANDIDATE_IDS or not candidate_id.startswith("M"):
            _raise(
                RegistryErrorCode.REGISTRY_CROSS_TYPE_INSERTION,
                "A noncandidate stable ID cannot enter the predictive candidate registry.",
            )
        if candidate_id in candidate_ids:
            _raise(
                RegistryErrorCode.REGISTRY_DUPLICATE_ID,
                "Candidate IDs must be unique.",
            )
        candidate_ids.append(candidate_id)
    if tuple(candidate_ids) != FROZEN_CANDIDATE_IDS:
        _raise(
            RegistryErrorCode.REGISTRY_FROZEN_SET_MISMATCH,
            "Predictive candidate membership and order must equal the frozen M0-M6 set.",
        )
    try:
        registry = CandidateRegistry.model_validate(payload)
    except ValidationError:
        _raise(
            RegistryErrorCode.REGISTRY_CONFIG_INVALID,
            "Candidate registry does not satisfy the canonical typed schema.",
        )
    baseline_candidate = next(
        item for item in registry.candidates if item.candidate_id == FROZEN_BASELINE_CANDIDATE_ID
    )
    if not baseline_candidate.enabled:
        _raise(
            RegistryErrorCode.REGISTRY_BASELINE_INVALID,
            "The frozen baseline candidate must be enabled.",
        )
    for candidate in registry.candidates:
        formula = tuple(term.value for term in candidate.formula_terms)
        semantics = tuple(
            item.value for item in candidate.feasibility_requirements.required_semantics
        )
        if (
            not candidate.enabled
            or candidate.version != _SUPPORTED_VERSION
            or candidate.model_family.value != "ols_fixed_effects"
            or formula != _FROZEN_FORMULA_TERMS[candidate.candidate_id]
            or semantics != _FROZEN_REQUIRED_SEMANTICS[candidate.candidate_id]
            or candidate.parameter_count_rule.kind != "realized_design_rank"
            or not candidate.parameter_count_rule.include_intercept
            or candidate.feasibility_requirements.min_rows != 80
            or candidate.feasibility_requirements.min_groups != 4
            or not candidate.feasibility_requirements.full_rank_required
        ):
            _raise(
                RegistryErrorCode.REGISTRY_FROZEN_SET_MISMATCH,
                "Candidate definitions must match the frozen Fill Pack structural library.",
            )
    return registry


def _read_repository_config(source_identifier: str) -> bytes:
    path = _resolve_repository_config(source_identifier)
    try:
        return path.read_bytes()
    except OSError:
        _raise(
            RegistryErrorCode.REGISTRY_CONFIG_NOT_FOUND,
            "An allowlisted configuration file could not be read.",
        )


def _resolve_repository_config(source_identifier: str) -> Path:
    _validate_relative_source_identifier(source_identifier)
    try:
        root = _CONFIG_ROOT.resolve(strict=True)
    except OSError:
        _raise(
            RegistryErrorCode.REGISTRY_CONFIG_NOT_FOUND,
            "The fixed repository configuration root is unavailable.",
        )
    candidate = _CONFIG_ROOT / PurePosixPath(source_identifier)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        _raise(
            RegistryErrorCode.REGISTRY_CONFIG_NOT_FOUND,
            "An allowlisted configuration file is missing.",
        )
    if not resolved.is_relative_to(root):
        _raise(
            RegistryErrorCode.REGISTRY_SYMLINK_ESCAPE,
            "A configuration source resolves outside the fixed repository config root.",
        )
    if not resolved.is_file():
        _raise(
            RegistryErrorCode.REGISTRY_CONFIG_INVALID,
            "An allowlisted configuration source is not a regular file.",
        )
    return resolved


def _validate_relative_source_identifier(source_identifier: str) -> None:
    if not isinstance(source_identifier, str) or not _SAFE_SOURCE_ID.fullmatch(source_identifier):
        _raise(
            RegistryErrorCode.REGISTRY_PATH_UNSAFE,
            "Configuration source identifier is not a safe repository-relative path.",
        )
    posix = PurePosixPath(source_identifier)
    windows = PureWindowsPath(source_identifier)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or "\\" in source_identifier
        or "://" in source_identifier
        or source_identifier.startswith("//")
        or any(part in {"", ".", ".."} for part in posix.parts)
        or posix.as_posix() != source_identifier
    ):
        _raise(
            RegistryErrorCode.REGISTRY_PATH_UNSAFE,
            "Configuration source identifier is not a safe repository-relative path.",
        )


def _parse_json_object(raw_bytes: bytes, *, manifest: bool) -> dict[str, object]:
    code = (
        RegistryErrorCode.REGISTRY_MANIFEST_INVALID
        if manifest
        else RegistryErrorCode.REGISTRY_CONFIG_INVALID
    )
    try:
        text = raw_bytes.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJsonKeyError, ValueError):
        _raise(code, "Registry JSON is invalid, duplicated, or non-finite.")
    if not isinstance(value, dict):
        _raise(code, "Registry configuration must be a JSON object.")
    return value


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKeyError
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    del value
    raise ValueError("non-finite JSON number")


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        _raise(
            RegistryErrorCode.REGISTRY_CONFIG_INVALID,
            "Configuration cannot be serialized as finite canonical JSON.",
        )


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _raise(
    code: RegistryErrorCode,
    message: str,
    *,
    logical_id: str | None = None,
) -> NoReturn:
    raise RegistryConfigError(code, message, logical_id=logical_id)


__all__ = [
    "ConfigSnapshot",
    "FROZEN_BASELINE_CANDIDATE_ID",
    "FROZEN_CANDIDATE_IDS",
    "RegistryConfigError",
    "RegistryConfigType",
    "RegistryErrorCode",
    "RegistryManifest",
    "RunRegistrySnapshot",
    "load_candidate_registry",
    "load_registry_manifest",
    "load_run_registry_snapshot",
    "verify_config_snapshot_hashes",
]
