
from __future__ import annotations

import json

from .app_service import AuditService


def main() -> int:
    print(json.dumps(AuditService().seed_status(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
