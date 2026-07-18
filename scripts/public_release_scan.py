from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

POLICY_RELATIVE_PATH = PurePosixPath("configs/release_scan.v1.json")
SUPPORTED_SCHEMA_ID = "riec-guard.public-release-scan-policy"
SUPPORTED_SCHEMA_VERSION = "1.0"
SUPPORTED_CONFIG_VERSION = "1.0.0"
MAX_POLICY_BYTES = 1024 * 1024
CODE_PATTERN = re.compile(r"[A-Z][A-Z0-9_]*")

BUILTIN_FINDING_CODES = frozenset(
    {
        "FILE_TOO_LARGE",
        "FORBIDDEN_EXTENSION",
        "FORBIDDEN_FILENAME",
        "FORBIDDEN_PATH_SEGMENT",
        "KNOWN_PRIVATE_HASH",
        "SUSPICIOUS_BINARY_FILE",
        "SYMLINK_REJECTED",
        "TEXT_DECODE_ERROR",
        "UNREADABLE_ENTRY",
        "UNSUPPORTED_ENTRY",
    }
)


class PolicyError(ValueError):
    """The release policy cannot be safely loaded or validated."""


class ScanRootError(ValueError):
    """The requested scan root is missing or unsafe."""


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    code: str
    detail: str

    def render(self) -> str:
        return f"- {self.path} [{self.code}]: {self.detail}"


@dataclass(frozen=True)
class RegexRule:
    code: str
    description: str
    pattern: re.Pattern[str]
    value_group: int | None = None
    allow_placeholders: bool = False


@dataclass(frozen=True)
class SignatureRule:
    code: str
    description: str
    signature: bytes
    offsets: tuple[int, ...]
    search_within_bytes: int


@dataclass(frozen=True)
class Policy:
    excluded_generated_directories: frozenset[str]
    forbidden_path_segments: frozenset[str]
    forbidden_filename_patterns: tuple[RegexRule, ...]
    forbidden_extensions: tuple[str, ...]
    binary_signatures: tuple[SignatureRule, ...]
    text_file_suffixes: frozenset[str]
    text_file_names: frozenset[str]
    max_file_size_bytes: int
    secret_pattern_rules: tuple[RegexRule, ...]
    absolute_local_path_rules: tuple[RegexRule, ...]
    placeholder_values: frozenset[str]
    placeholder_patterns: tuple[re.Pattern[str], ...]
    known_private_sha256: frozenset[str]
    allowlist_exceptions: dict[str, frozenset[str]]

    def is_allowed(self, relative_path: str, code: str) -> bool:
        return code in self.allowlist_exceptions.get(relative_path, frozenset())


class _DuplicateKeyError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(key)
        result[key] = value
    return result


def _fail(message: str) -> NoReturn:
    raise PolicyError(message)


def _expect_object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        _fail(f"{label} must be an object")
    return value


def _require_keys(value: dict[str, Any], required: set[str], label: str) -> None:
    present = set(value)
    if present != required:
        _fail(f"{label} has missing or unsupported fields")


def _expect_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be a non-empty string")
    return value


def _expect_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        _fail(f"{label} must be a boolean")
    return value


def _expect_int(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _fail(f"{label} must be an integer of at least {minimum}")
    return value


def _expect_string_list(
    value: object, label: str, *, allow_empty_strings: bool = False
) -> tuple[str, ...]:
    if not isinstance(value, list):
        _fail(f"{label} must be a list")
    if allow_empty_strings:
        if not all(isinstance(item, str) for item in value):
            _fail(f"{label} items must be strings")
        items = tuple(value)
    else:
        items = tuple(_expect_string(item, f"{label} item") for item in value)
    if len(items) != len(set(items)):
        _fail(f"{label} must not contain duplicates")
    return items


def _validate_code(value: object, label: str) -> str:
    code = _expect_string(value, label)
    if CODE_PATTERN.fullmatch(code) is None:
        _fail(f"{label} must be a stable uppercase finding code")
    return code


def _compile_pattern(pattern: str, *, case_sensitive: bool, label: str) -> re.Pattern[str]:
    flags = re.MULTILINE
    if not case_sensitive:
        flags |= re.IGNORECASE
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise PolicyError(f"{label} contains an invalid regular expression") from exc


def _parse_regex_rules(
    value: object,
    label: str,
    *,
    secret_rules: bool = False,
) -> tuple[RegexRule, ...]:
    if not isinstance(value, list) or not value:
        _fail(f"{label} must be a non-empty list")
    rules: list[RegexRule] = []
    for index, raw in enumerate(value):
        item_label = f"{label}[{index}]"
        item = _expect_object(raw, item_label)
        common = {"code", "description", "pattern", "case_sensitive"}
        required = common | ({"value_group", "allow_placeholders"} if secret_rules else set())
        _require_keys(item, required, item_label)
        code = _validate_code(item["code"], f"{item_label}.code")
        description = _expect_string(item["description"], f"{item_label}.description")
        case_sensitive = _expect_bool(
            item["case_sensitive"], f"{item_label}.case_sensitive"
        )
        pattern = _compile_pattern(
            _expect_string(item["pattern"], f"{item_label}.pattern"),
            case_sensitive=case_sensitive,
            label=f"{item_label}.pattern",
        )
        value_group: int | None = None
        allow_placeholders = False
        if secret_rules:
            raw_group = item["value_group"]
            if raw_group is not None:
                value_group = _expect_int(raw_group, f"{item_label}.value_group", minimum=1)
                if value_group > pattern.groups:
                    _fail(f"{item_label}.value_group does not exist in its pattern")
            allow_placeholders = _expect_bool(
                item["allow_placeholders"], f"{item_label}.allow_placeholders"
            )
            if allow_placeholders and value_group is None:
                _fail(f"{item_label} needs a value_group when placeholders are allowed")
        rules.append(
            RegexRule(
                code=code,
                description=description,
                pattern=pattern,
                value_group=value_group,
                allow_placeholders=allow_placeholders,
            )
        )
    codes = [rule.code for rule in rules]
    if len(codes) != len(set(codes)):
        _fail(f"{label} contains duplicate finding codes")
    return tuple(rules)


def _parse_signatures(value: object) -> tuple[SignatureRule, ...]:
    label = "binary_signatures"
    if not isinstance(value, list) or not value:
        _fail(f"{label} must be a non-empty list")
    rules: list[SignatureRule] = []
    for index, raw in enumerate(value):
        item_label = f"{label}[{index}]"
        item = _expect_object(raw, item_label)
        _require_keys(
            item,
            {"code", "description", "hex", "offsets", "search_within_bytes"},
            item_label,
        )
        code = _validate_code(item["code"], f"{item_label}.code")
        description = _expect_string(item["description"], f"{item_label}.description")
        hex_value = _expect_string(item["hex"], f"{item_label}.hex")
        if len(hex_value) % 2 or re.fullmatch(r"[0-9a-fA-F]+", hex_value) is None:
            _fail(f"{item_label}.hex must contain complete hexadecimal bytes")
        signature = bytes.fromhex(hex_value)
        if len(signature) < 2:
            _fail(f"{item_label}.hex signature is too short")
        raw_offsets = item["offsets"]
        if not isinstance(raw_offsets, list):
            _fail(f"{item_label}.offsets must be a list")
        offsets = tuple(
            _expect_int(offset, f"{item_label}.offsets item") for offset in raw_offsets
        )
        if len(offsets) != len(set(offsets)):
            _fail(f"{item_label}.offsets must not contain duplicates")
        search_within_bytes = _expect_int(
            item["search_within_bytes"], f"{item_label}.search_within_bytes"
        )
        if not offsets and search_within_bytes == 0:
            _fail(f"{item_label} must define an offset or a search window")
        rules.append(
            SignatureRule(
                code=code,
                description=description,
                signature=signature,
                offsets=offsets,
                search_within_bytes=search_within_bytes,
            )
        )
    return tuple(rules)


def _parse_allowlist(value: object, valid_codes: frozenset[str]) -> dict[str, frozenset[str]]:
    label = "allowlist_exceptions"
    if not isinstance(value, list):
        _fail(f"{label} must be a list")
    result: dict[str, frozenset[str]] = {}
    for index, raw in enumerate(value):
        item_label = f"{label}[{index}]"
        item = _expect_object(raw, item_label)
        _require_keys(item, {"path", "finding_codes", "reason"}, item_label)
        path = _expect_string(item["path"], f"{item_label}.path")
        parsed_path = PurePosixPath(path)
        if parsed_path.is_absolute() or ".." in parsed_path.parts or path != parsed_path.as_posix():
            _fail(f"{item_label}.path must be a normalized relative path")
        codes = frozenset(_expect_string_list(item["finding_codes"], f"{item_label}.finding_codes"))
        if not codes or not codes <= valid_codes:
            _fail(f"{item_label}.finding_codes contains an unsupported code")
        _expect_string(item["reason"], f"{item_label}.reason")
        if path in result:
            _fail(f"{label} contains a duplicate path")
        result[path] = codes
    return result


def _validate_simple_names(items: tuple[str, ...], label: str) -> frozenset[str]:
    normalized: list[str] = []
    for item in items:
        if item in {".", ".."} or "/" in item or "\\" in item:
            _fail(f"{label} entries must be single path segments")
        lowered = item.casefold()
        if lowered in normalized:
            _fail(f"{label} contains case-insensitive duplicates")
        normalized.append(lowered)
    return frozenset(normalized)


def _validate_extensions(items: tuple[str, ...], label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    for item in items:
        lowered = item.casefold()
        if not lowered.startswith(".") or "/" in lowered or "\\" in lowered:
            _fail(f"{label} entries must be dotted filename suffixes")
        if lowered in normalized:
            _fail(f"{label} contains case-insensitive duplicates")
        normalized.append(lowered)
    return tuple(sorted(normalized, key=lambda extension: (-len(extension), extension)))


def _policy_from_object(raw: object) -> Policy:
    data = _expect_object(raw, "policy")
    required = {
        "schema_id",
        "schema_version",
        "config_version",
        "excluded_generated_directories",
        "forbidden_path_segments",
        "forbidden_filename_patterns",
        "forbidden_extensions",
        "binary_signatures",
        "text_file_suffixes",
        "text_file_names",
        "max_file_size_bytes",
        "secret_pattern_rules",
        "absolute_local_path_rules",
        "placeholder_values",
        "placeholder_patterns",
        "known_private_sha256",
        "allowlist_exceptions",
    }
    _require_keys(data, required, "policy")
    if data["schema_id"] != SUPPORTED_SCHEMA_ID:
        _fail("policy schema_id is unsupported")
    if data["schema_version"] != SUPPORTED_SCHEMA_VERSION:
        _fail("policy schema_version is unsupported")
    if data["config_version"] != SUPPORTED_CONFIG_VERSION:
        _fail("policy config_version is unsupported")

    filename_rules = _parse_regex_rules(
        data["forbidden_filename_patterns"], "forbidden_filename_patterns"
    )
    secret_rules = _parse_regex_rules(
        data["secret_pattern_rules"], "secret_pattern_rules", secret_rules=True
    )
    absolute_rules = _parse_regex_rules(
        data["absolute_local_path_rules"], "absolute_local_path_rules"
    )
    signatures = _parse_signatures(data["binary_signatures"])
    configured_codes = frozenset(
        [rule.code for rule in filename_rules]
        + [rule.code for rule in secret_rules]
        + [rule.code for rule in absolute_rules]
        + [rule.code for rule in signatures]
    )
    valid_codes = BUILTIN_FINDING_CODES | configured_codes

    placeholder_patterns = tuple(
        _compile_pattern(pattern, case_sensitive=False, label="placeholder_patterns item")
        for pattern in _expect_string_list(data["placeholder_patterns"], "placeholder_patterns")
    )
    hashes = _expect_string_list(data["known_private_sha256"], "known_private_sha256")
    normalized_hashes: list[str] = []
    for digest in hashes:
        lowered = digest.casefold()
        if re.fullmatch(r"[0-9a-f]{64}", lowered) is None:
            _fail("known_private_sha256 entries must be complete SHA-256 values")
        normalized_hashes.append(lowered)

    return Policy(
        excluded_generated_directories=_validate_simple_names(
            _expect_string_list(
                data["excluded_generated_directories"], "excluded_generated_directories"
            ),
            "excluded_generated_directories",
        ),
        forbidden_path_segments=_validate_simple_names(
            _expect_string_list(data["forbidden_path_segments"], "forbidden_path_segments"),
            "forbidden_path_segments",
        ),
        forbidden_filename_patterns=filename_rules,
        forbidden_extensions=_validate_extensions(
            _expect_string_list(data["forbidden_extensions"], "forbidden_extensions"),
            "forbidden_extensions",
        ),
        binary_signatures=signatures,
        text_file_suffixes=frozenset(
            _validate_extensions(
                _expect_string_list(data["text_file_suffixes"], "text_file_suffixes"),
                "text_file_suffixes",
            )
        ),
        text_file_names=frozenset(
            _expect_string_list(data["text_file_names"], "text_file_names")
        ),
        max_file_size_bytes=_expect_int(
            data["max_file_size_bytes"], "max_file_size_bytes", minimum=1
        ),
        secret_pattern_rules=secret_rules,
        absolute_local_path_rules=absolute_rules,
        placeholder_values=frozenset(
            value.casefold()
            for value in _expect_string_list(
                data["placeholder_values"],
                "placeholder_values",
                allow_empty_strings=True,
            )
        ),
        placeholder_patterns=placeholder_patterns,
        known_private_sha256=frozenset(normalized_hashes),
        allowlist_exceptions=_parse_allowlist(data["allowlist_exceptions"], valid_codes),
    )


def _validate_scan_root(root: Path) -> Path:
    try:
        root_lstat = root.lstat()
    except OSError as exc:
        raise ScanRootError("scan root does not exist or is unreadable") from exc
    if stat.S_ISLNK(root_lstat.st_mode):
        raise ScanRootError("scan root must not be a symbolic link")
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise ScanRootError("scan root cannot be safely resolved") from exc
    if not resolved.is_dir():
        raise ScanRootError("scan root must be a directory")
    return resolved


def load_policy(root: Path, config_path: Path | None = None) -> Policy:
    candidate = config_path if config_path is not None else root / POLICY_RELATIVE_PATH
    try:
        candidate_lstat = candidate.lstat()
        resolved_config = candidate.resolve(strict=True)
    except OSError as exc:
        raise PolicyError("release policy is missing or unreadable") from exc
    if stat.S_ISLNK(candidate_lstat.st_mode) or not stat.S_ISREG(candidate_lstat.st_mode):
        raise PolicyError("release policy must be a regular non-symlink file")
    if not resolved_config.is_relative_to(root):
        raise PolicyError("release policy must remain inside the scan root")
    if candidate_lstat.st_size > MAX_POLICY_BYTES:
        raise PolicyError("release policy exceeds the safe configuration size")
    try:
        content = resolved_config.read_text(encoding="utf-8")
        raw = json.loads(content, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError, _DuplicateKeyError) as exc:
        raise PolicyError("release policy is malformed or unreadable") from exc
    return _policy_from_object(raw)


def _relative_display(path: Path, root: Path) -> str:
    relative = path.relative_to(root).as_posix()
    return relative.encode("unicode_escape").decode("ascii")


def _add_finding(
    findings: set[Finding],
    policy: Policy,
    relative_path: str,
    code: str,
    detail: str,
) -> None:
    if not policy.is_allowed(relative_path, code):
        findings.add(Finding(path=relative_path, code=code, detail=detail))


def _scan_path(
    path: Path,
    root: Path,
    policy: Policy,
    findings: set[Finding],
    *,
    is_file: bool,
) -> str:
    relative_path = _relative_display(path, root)
    relative = path.relative_to(root)
    forbidden_parts = {
        part.casefold() for part in relative.parts if part.casefold() in policy.forbidden_path_segments
    }
    if forbidden_parts:
        _add_finding(
            findings,
            policy,
            relative_path,
            "FORBIDDEN_PATH_SEGMENT",
            "path contains a release-forbidden segment",
        )
    for rule in policy.forbidden_filename_patterns:
        if rule.pattern.search(relative.name):
            _add_finding(findings, policy, relative_path, rule.code, rule.description)
    if is_file:
        lowered_name = relative.name.casefold()
        if any(lowered_name.endswith(extension) for extension in policy.forbidden_extensions):
            _add_finding(
                findings,
                policy,
                relative_path,
                "FORBIDDEN_EXTENSION",
                "file has a release-forbidden extension",
            )
    return relative_path


def _read_regular_file(path: Path, expected_stat: os.stat_result, limit: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened_stat = os.fstat(descriptor)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise OSError("entry changed type during scan")
        if (opened_stat.st_dev, opened_stat.st_ino) != (expected_stat.st_dev, expected_stat.st_ino):
            raise OSError("entry changed identity during scan")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            return handle.read(limit + 1)
    finally:
        os.close(descriptor)


def _signature_matches(content: bytes, rule: SignatureRule) -> bool:
    if any(content[offset : offset + len(rule.signature)] == rule.signature for offset in rule.offsets):
        return True
    if rule.search_within_bytes:
        search_end = min(len(content), rule.search_within_bytes)
        return content.find(rule.signature, 0, search_end) != -1
    return False


def _is_placeholder(value: str, policy: Policy) -> bool:
    normalized = value.strip().strip("\"'").strip()
    if normalized.casefold() in policy.placeholder_values:
        return True
    return any(pattern.fullmatch(normalized) is not None for pattern in policy.placeholder_patterns)


def _scan_text(
    text: str,
    relative_path: str,
    policy: Policy,
    findings: set[Finding],
) -> None:
    for rule in policy.secret_pattern_rules:
        for match in rule.pattern.finditer(text):
            if rule.allow_placeholders and rule.value_group is not None:
                value = match.group(rule.value_group)
                if _is_placeholder(value, policy):
                    continue
            _add_finding(findings, policy, relative_path, rule.code, rule.description)
            break
    for rule in policy.absolute_local_path_rules:
        if rule.pattern.search(text):
            _add_finding(findings, policy, relative_path, rule.code, rule.description)


def _scan_file(
    path: Path,
    root: Path,
    policy: Policy,
    findings: set[Finding],
    relative_path: str,
) -> None:
    try:
        entry_stat = path.stat(follow_symlinks=False)
    except OSError:
        _add_finding(
            findings,
            policy,
            relative_path,
            "UNREADABLE_ENTRY",
            "file metadata could not be read safely",
        )
        return
    if entry_stat.st_size > policy.max_file_size_bytes:
        _add_finding(
            findings,
            policy,
            relative_path,
            "FILE_TOO_LARGE",
            "file exceeds the configured release size limit",
        )
        return
    try:
        content = _read_regular_file(path, entry_stat, policy.max_file_size_bytes)
    except OSError:
        _add_finding(
            findings,
            policy,
            relative_path,
            "UNREADABLE_ENTRY",
            "file content could not be read safely",
        )
        return
    if len(content) > policy.max_file_size_bytes:
        _add_finding(
            findings,
            policy,
            relative_path,
            "FILE_TOO_LARGE",
            "file grew beyond the configured release size limit during scanning",
        )
        return

    for rule in policy.binary_signatures:
        if _signature_matches(content, rule):
            _add_finding(findings, policy, relative_path, rule.code, rule.description)

    digest = hashlib.sha256(content).hexdigest()
    if digest in policy.known_private_sha256:
        _add_finding(
            findings,
            policy,
            relative_path,
            "KNOWN_PRIVATE_HASH",
            "file matches a configured non-public SHA-256",
        )

    relative = path.relative_to(root)
    text_expected = (
        any(relative.name.casefold().endswith(suffix) for suffix in policy.text_file_suffixes)
        or relative.name in policy.text_file_names
    )
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        code = "TEXT_DECODE_ERROR" if text_expected else "SUSPICIOUS_BINARY_FILE"
        detail = (
            "configured text file is not valid UTF-8"
            if text_expected
            else "unclassified non-text file cannot be safely released"
        )
        _add_finding(findings, policy, relative_path, code, detail)
        return

    unsafe_controls = sum(
        1 for character in text if ord(character) < 32 and character not in "\t\n\r"
    )
    if "\x00" in text or unsafe_controls > max(2, len(text) // 100):
        _add_finding(
            findings,
            policy,
            relative_path,
            "SUSPICIOUS_BINARY_FILE",
            "file contains unsafe binary or control content",
        )
        return
    _scan_text(text, relative_path, policy, findings)


def scan_repository(root: Path, policy: Policy) -> list[Finding]:
    findings: set[Finding] = set()
    pending: list[Path] = [root]
    while pending:
        directory = pending.pop()
        try:
            directory_lstat = directory.lstat()
            resolved_directory = directory.resolve(strict=True)
            if (
                stat.S_ISLNK(directory_lstat.st_mode)
                or not stat.S_ISDIR(directory_lstat.st_mode)
                or not resolved_directory.is_relative_to(root)
            ):
                raise OSError("directory changed identity during scan")
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name.casefold())
        except OSError:
            relative_path = "." if directory == root else _relative_display(directory, root)
            _add_finding(
                findings,
                policy,
                relative_path,
                "UNREADABLE_ENTRY",
                "directory could not be traversed safely",
            )
            continue
        for entry in entries:
            path = Path(entry.path)
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError:
                relative_path = _relative_display(path, root)
                _add_finding(
                    findings,
                    policy,
                    relative_path,
                    "UNREADABLE_ENTRY",
                    "entry metadata could not be read safely",
                )
                continue
            if stat.S_ISLNK(entry_stat.st_mode):
                relative_path = _scan_path(
                    path, root, policy, findings, is_file=False
                )
                _add_finding(
                    findings,
                    policy,
                    relative_path,
                    "SYMLINK_REJECTED",
                    "symbolic links are ambiguous release content and are not followed",
                )
                continue
            if stat.S_ISDIR(entry_stat.st_mode):
                if entry.name in policy.excluded_generated_directories:
                    continue
                _scan_path(path, root, policy, findings, is_file=False)
                pending.append(path)
                continue
            if stat.S_ISREG(entry_stat.st_mode):
                relative_path = _scan_path(path, root, policy, findings, is_file=True)
                _scan_file(path, root, policy, findings, relative_path)
                continue
            relative_path = _scan_path(path, root, policy, findings, is_file=False)
            _add_finding(
                findings,
                policy,
                relative_path,
                "UNSUPPORTED_ENTRY",
                "filesystem entry is not a regular file or directory",
            )
    return sorted(findings)


def _print_failure(code: str, detail: str) -> None:
    print("Public release scan failed:")
    print(Finding(path=".", code=code, detail=detail).render())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan a proposed clean-room public repository")
    parser.add_argument("root", nargs="?", default=".", help="repository root to scan")
    parser.add_argument(
        "--config",
        type=Path,
        help="policy path inside the requested root (defaults to configs/release_scan.v1.json)",
    )
    args = parser.parse_args(argv)
    try:
        root = _validate_scan_root(Path(args.root))
    except ScanRootError:
        _print_failure("UNSAFE_SCAN_ROOT", "requested scan root is missing or unsafe")
        return 2
    try:
        policy = load_policy(root, args.config)
    except PolicyError:
        _print_failure("CONFIG_INVALID", "release policy is missing, malformed, or unsupported")
        return 2
    try:
        findings = scan_repository(root, policy)
    except Exception:
        _print_failure("SCANNER_INTERNAL_ERROR", "scanner failed closed during repository inspection")
        return 3
    if findings:
        print("Public release scan failed:")
        for finding in findings:
            print(finding.render())
        return 1
    print("Public release scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
