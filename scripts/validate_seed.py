
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "README.md", "AGENTS.md", "pyproject.toml", "src/riec_guard/__init__.py",
    "src/riec_guard/app_service.py", "schemas/SCHEMA_INDEX.json",
    "configs/candidates.fill.v1.json", "docs/PRIOR_WORK_BOUNDARY.md",
    "docs/BUILD_WEEK_DELTA.md", "scripts/public_release_scan.py",
]


def main() -> int:
    missing = [p for p in REQUIRED if not (ROOT / p).exists()]
    if missing:
        print("Missing required seed files:", *missing, sep="\n- ")
        return 1
    for path in (ROOT / "schemas").rglob("*.json"):
        json.loads(path.read_text(encoding="utf-8"))
    for path in (ROOT / "configs").rglob("*.json"):
        json.loads(path.read_text(encoding="utf-8"))
    sys.path.insert(0, str(ROOT / "src"))
    from riec_guard.app_service import AuditService
    status = AuditService().seed_status()
    assert status["status"] == "seed"
    print(f"Seed validation passed: {len(list((ROOT / 'schemas').rglob('*.json')))} JSON artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
