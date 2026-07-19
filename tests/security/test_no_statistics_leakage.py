from __future__ import annotations

import ast
import inspect
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from riec_guard.telemetry.manifest import verify_manifest
from riec_guard.telemetry.models import RunManifest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
GPT_ROOT = REPOSITORY_ROOT / "src/riec_guard/gpt"
STREAMLIT_ENTRY_POINT = REPOSITORY_ROOT / "streamlit_app.py"
RUN_MANIFEST_EXAMPLE = REPOSITORY_ROOT / "schemas/examples/run_manifest.example.json"
PRE_STATISTICS_BOUNDARY_PATHS = tuple(
    REPOSITORY_ROOT / relative_path
    for relative_path in (
        "src/riec_guard/contract/canonicalize.py",
        "src/riec_guard/contract/models.py",
        "src/riec_guard/contract/profiler.py",
        "src/riec_guard/contract/schema_loader.py",
        "src/riec_guard/contract/validator.py",
        "src/riec_guard/evidence/ids.py",
        "src/riec_guard/evidence/ledger.py",
        "src/riec_guard/evidence/models.py",
        "src/riec_guard/evidence/provenance.py",
        "src/riec_guard/telemetry/manifest.py",
        "src/riec_guard/telemetry/models.py",
    )
)

FORBIDDEN_SCIENTIFIC_IMPORT_ROOTS = frozenset(
    {
        "jax",
        "lightgbm",
        "numpy",
        "pandas",
        "patsy",
        "polars",
        "scipy",
        "sklearn",
        "statistics",
        "statsmodels",
        "tensorflow",
        "torch",
        "xgboost",
    }
)
FORBIDDEN_DYNAMIC_IMPORT_ROOTS = frozenset({"importlib", "pkgutil", "runpy", "zipimport"})
FORBIDDEN_DYNAMIC_CALLS = frozenset(
    {
        "__import__",
        "compile",
        "eval",
        "exec",
        "exec_module",
        "find_loader",
        "find_spec",
        "import_module",
        "load_module",
        "module_from_spec",
        "spec_from_file_location",
    }
)
FORBIDDEN_STATISTICAL_CALLS = frozenset(
    {
        "anderson",
        "bootstrap",
        "corr",
        "corrcoef",
        "cov",
        "cross_val_score",
        "fit",
        "glm",
        "groupkfold",
        "kfold",
        "lstsq",
        "mean",
        "median",
        "mixedlm",
        "ols",
        "percentile",
        "polyfit",
        "predict",
        "quantile",
        "shapiro",
        "std",
        "stdev",
        "ttest_1samp",
        "ttest_ind",
        "var",
        "variance",
    }
)
FORBIDDEN_IMPLEMENTATION_NAME_FRAGMENTS = (
    "action_state_calculation",
    "calculate_headroom",
    "calculate_recommendation",
    "calculate_riec",
    "compute_headroom",
    "compute_recommendation",
    "compute_riec",
    "cross_validate",
    "fit_candidate",
    "ordered_stability_screen",
    "run_headroom_protocol",
    "run_uncertainty",
    "select_candidate",
)


def _boundary_paths() -> tuple[Path, ...]:
    gpt_paths = tuple(
        sorted(
            GPT_ROOT.rglob("*.py"),
            key=lambda path: path.relative_to(REPOSITORY_ROOT).as_posix(),
        )
    )
    assert gpt_paths, "the GPT package must contain at least one Python module"
    assert STREAMLIT_ENTRY_POINT.is_file(), "the Streamlit entry point must exist"
    return (STREAMLIT_ENTRY_POINT, *gpt_paths)


def _relative_path(path: Path) -> str:
    return path.relative_to(REPOSITORY_ROOT).as_posix()


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id.casefold()
    if isinstance(node.func, ast.Attribute):
        return node.func.attr.casefold()
    return ""


def _ast_findings(path: Path) -> tuple[tuple[str, int, str, str], ...]:
    relative_path = _relative_path(path)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative_path)
    findings: list[tuple[str, int, str, str]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root in FORBIDDEN_SCIENTIFIC_IMPORT_ROOTS:
                    findings.append((relative_path, node.lineno, "scientific import", alias.name))
                if root in FORBIDDEN_DYNAMIC_IMPORT_ROOTS:
                    findings.append((relative_path, node.lineno, "dynamic import", alias.name))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            root = module.split(".", 1)[0]
            if root in FORBIDDEN_SCIENTIFIC_IMPORT_ROOTS:
                findings.append((relative_path, node.lineno, "scientific import", module))
            if root in FORBIDDEN_DYNAMIC_IMPORT_ROOTS:
                findings.append((relative_path, node.lineno, "dynamic import", module))
        elif isinstance(node, ast.Call):
            call_name = _call_name(node)
            is_dynamic_call = (
                isinstance(node.func, ast.Name)
                and call_name in FORBIDDEN_DYNAMIC_CALLS
                or isinstance(node.func, ast.Attribute)
                and call_name in FORBIDDEN_DYNAMIC_CALLS - {"compile", "eval", "exec"}
            )
            if is_dynamic_call:
                findings.append((relative_path, node.lineno, "dynamic execution", call_name))
            if call_name in FORBIDDEN_STATISTICAL_CALLS:
                findings.append((relative_path, node.lineno, "statistical call", call_name))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            normalized_name = node.name.casefold()
            marker = next(
                (
                    fragment
                    for fragment in FORBIDDEN_IMPLEMENTATION_NAME_FRAGMENTS
                    if fragment in normalized_name
                ),
                None,
            )
            if marker is not None:
                findings.append((relative_path, node.lineno, "statistical definition", marker))

    return tuple(sorted(findings))


def test_gpt_and_ui_modules_contain_no_statistical_implementation() -> None:
    targets = _boundary_paths()
    relative_paths = tuple(_relative_path(path) for path in targets)
    assert relative_paths[0] == "streamlit_app.py"
    assert relative_paths[1:] == tuple(sorted(relative_paths[1:]))
    assert len(relative_paths) == len(set(relative_paths))

    findings = tuple(finding for path in targets for finding in _ast_findings(path))
    assert findings == ()


def test_contract_evidence_and_manifest_layers_contain_no_scheduled_method_runtime() -> None:
    assert all(path.is_file() for path in PRE_STATISTICS_BOUNDARY_PATHS)
    findings = tuple(
        finding for path in PRE_STATISTICS_BOUNDARY_PATHS for finding in _ast_findings(path)
    )
    assert findings == ()


def test_isolated_gpt_and_ui_imports_load_no_scientific_stack() -> None:
    probe = """
import importlib
import importlib.util
import json
import sys
from pathlib import Path

repository_root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(repository_root / "src"))
sys.path.insert(0, str(repository_root))

importlib.import_module("riec_guard.gpt")
spec = importlib.util.spec_from_file_location(
    "_riec_guard_g1_streamlit_boundary",
    repository_root / "streamlit_app.py",
)
if spec is None or spec.loader is None:
    raise SystemExit("streamlit boundary import specification is unavailable")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

forbidden = set(json.loads(sys.argv[2]))
loaded_roots = {name.split(".", 1)[0] for name in sys.modules}
print(json.dumps(sorted(loaded_roots & forbidden), separators=(",", ":")))
"""
    completed = subprocess.run(
        (
            sys.executable,
            "-I",
            "-B",
            "-c",
            probe,
            str(REPOSITORY_ROOT),
            json.dumps(sorted(FORBIDDEN_SCIENTIFIC_IMPORT_ROOTS)),
        ),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=15,
        shell=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == []


def test_runtime_manifest_verification_requires_explicit_registry_binding(
    tmp_path: Path,
) -> None:
    payload = json.loads(RUN_MANIFEST_EXAMPLE.read_text(encoding="utf-8"))
    manifest = RunManifest.model_validate(payload)
    artifact_root = tmp_path / manifest.run_id / "artifacts"
    artifact_root.mkdir(parents=True)

    signature = inspect.signature(verify_manifest)
    for parameter_name in (
        "expected_registry_snapshot",
        "expected_action_engine_version",
    ):
        parameter = signature.parameters[parameter_name]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is inspect.Parameter.empty

    unbound_verify = cast(Callable[..., object], verify_manifest)
    with pytest.raises(TypeError) as caught:
        unbound_verify(manifest, artifact_root=artifact_root)

    diagnostic = str(caught.value)
    assert "expected_registry_snapshot" in diagnostic
    assert "expected_action_engine_version" in diagnostic
