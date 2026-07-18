
from __future__ import annotations

import os
import tempfile
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


SettingsMode = Literal["public", "private"]

_REPO_ROOT = Path(__file__).resolve().parents[2]
_RUN_SUBDIRECTORIES = ("inputs", "normalized", "artifacts", "telemetry")


class SettingsValidationError(ValueError):
    """Raised for public-facing settings errors without exposing local paths."""


def _default_ephemeral_root() -> Path:
    return Path(tempfile.gettempdir()) / "riec-guard" / "runs"


def _parse_bool(value: str | None, *, default: bool) -> bool:
    if value is None or value == "":
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise SettingsValidationError("hosted_mode must be a boolean setting")


def _normalize_root(value: Path | str, *, field_name: str) -> Path:
    try:
        root = Path(value).expanduser()
        if not root.is_absolute():
            root = Path.cwd() / root
        return root.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise SettingsValidationError(f"{field_name} is not a valid root") from exc


def _contains_or_equals(parent: Path, child: Path) -> bool:
    return child == parent or child.is_relative_to(parent)


def _reject_repo_runtime_root(root: Path, *, field_name: str) -> None:
    if _contains_or_equals(_REPO_ROOT, root):
        raise SettingsValidationError(f"{field_name} must not be the repository root or inside it")


def _reject_overlapping_roots(
    left: Path,
    *,
    left_name: str,
    right: Path,
    right_name: str,
) -> None:
    if _contains_or_equals(left, right) or _contains_or_equals(right, left):
        raise SettingsValidationError(f"{left_name} and {right_name} must be different roots")


def _new_run_id() -> str:
    return f"RUN-{uuid.uuid4().hex}"


@dataclass(frozen=True, slots=True)
class RunRoots:
    """Run-scoped runtime directories generated from an internal run ID."""

    run_id: str
    run_root: Path
    inputs: Path
    normalized: Path
    artifacts: Path
    telemetry: Path

    @classmethod
    def under(cls, ephemeral_root: Path, run_id: str) -> "RunRoots":
        run_root = ephemeral_root / run_id
        return cls(
            run_id=run_id,
            run_root=run_root,
            inputs=run_root / "inputs",
            normalized=run_root / "normalized",
            artifacts=run_root / "artifacts",
            telemetry=run_root / "telemetry",
        )


@dataclass(frozen=True, slots=True)
class SeedSettings:
    """Immutable public-first runtime settings."""

    mode: SettingsMode = "public"
    hosted_mode: bool = True
    model: str = "gpt-5.6-sol"
    ephemeral_root: Path = field(default_factory=_default_ephemeral_root)
    private_data_root: Path | None = None

    def __post_init__(self) -> None:
        if self.mode not in {"public", "private"}:
            raise SettingsValidationError("mode must be public or private")
        if self.hosted_mode and self.mode == "private":
            raise SettingsValidationError("private mode is not available in hosted_mode")

        ephemeral_root = _normalize_root(self.ephemeral_root, field_name="ephemeral_root")
        _reject_repo_runtime_root(ephemeral_root, field_name="ephemeral_root")
        object.__setattr__(self, "ephemeral_root", ephemeral_root)

        if self.mode == "public":
            if self.private_data_root is not None:
                raise SettingsValidationError("private_data_root is not accepted in public mode")
            return

        if self.private_data_root is None:
            raise SettingsValidationError("private_data_root is required for private mode")
        private_data_root = _normalize_root(self.private_data_root, field_name="private_data_root")
        _reject_overlapping_roots(
            ephemeral_root,
            left_name="ephemeral_root",
            right=private_data_root,
            right_name="private_data_root",
        )
        object.__setattr__(self, "private_data_root", private_data_root)

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "SeedSettings":
        env = os.environ if environ is None else environ
        if "RIEC_GUARD_PRIVATE_DATA_ROOT" in env or "RIEC_GUARD_PRIVATE_ROOT" in env:
            raise SettingsValidationError("private_data_root is not accepted in public settings")
        if env.get("RIEC_GUARD_MODE", "public").strip().lower() == "private":
            raise SettingsValidationError("private mode is not accepted in public settings")

        configured_root = env.get("RIEC_GUARD_EPHEMERAL_ROOT")
        ephemeral_root = Path(configured_root) if configured_root else _default_ephemeral_root()
        return cls(
            mode="public",
            hosted_mode=_parse_bool(env.get("RIEC_GUARD_HOSTED_MODE"), default=True),
            model=env.get("RIEC_GUARD_MODEL", "gpt-5.6-sol") or "gpt-5.6-sol",
            ephemeral_root=ephemeral_root,
        )

    @classmethod
    def private_local(
        cls,
        *,
        ephemeral_root: Path | str,
        private_data_root: Path | str,
        model: str = "gpt-5.6-sol",
    ) -> "SeedSettings":
        return cls(
            mode="private",
            hosted_mode=False,
            model=model,
            ephemeral_root=Path(ephemeral_root),
            private_data_root=Path(private_data_root),
        )

    @property
    def public_mode(self) -> bool:
        return self.mode == "public"

    def assert_safe(self) -> None:
        if not self.public_mode or self.hosted_mode and self.mode == "private":
            raise SettingsValidationError("private mode is not available in the public runtime")

    def create_run_roots(self) -> RunRoots:
        for _ in range(100):
            roots = RunRoots.under(self.ephemeral_root, _new_run_id())
            try:
                roots.run_root.mkdir(parents=True, exist_ok=False)
            except FileExistsError:
                continue
            for directory_name in _RUN_SUBDIRECTORIES:
                (roots.run_root / directory_name).mkdir()
            return roots
        raise SettingsValidationError("run_root could not be created")


RuntimeSettings = SeedSettings
