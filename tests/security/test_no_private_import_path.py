
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_public_package_has_no_private_adapter_module():
    assert not any("private" in p.name.lower() for p in (ROOT / "src/riec_guard").rglob("*.py"))
