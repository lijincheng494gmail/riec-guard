
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def test_seed_service_imports_and_is_public_safe():
    from riec_guard.app_service import AuditService
    status = AuditService().seed_status()
    assert status == {"status": "seed", "next_task": "TASK-001"}


def test_no_private_directory_in_repo():
    assert not (ROOT / "private").exists()
