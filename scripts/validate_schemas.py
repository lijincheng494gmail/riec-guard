
"""TASK-007 replaces this seed helper with canonical jsonschema validation."""

from pathlib import Path
import json

root = Path(__file__).resolve().parents[1] / "schemas"
for path in root.rglob("*.json"):
    json.loads(path.read_text(encoding="utf-8"))
print("All schema JSON files parsed successfully")
