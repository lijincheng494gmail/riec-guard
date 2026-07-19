from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def main() -> int:
    from riec_guard.contract.schema_loader import (
        SchemaRegistryError,
        load_schema_registry,
    )

    try:
        registry = load_schema_registry()
    except SchemaRegistryError as exc:
        print(f"Schema validation failed [{exc.code}]: {exc}")
        return 1
    canonical_count = len(registry.canonical())
    projection_count = len(registry.gpt_projections())
    print(
        f"Schema validation passed: {canonical_count} canonical and "
        f"{projection_count} GPT projection schemas"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
