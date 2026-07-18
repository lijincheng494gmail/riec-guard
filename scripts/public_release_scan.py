
from __future__ import annotations

import re
import sys
from pathlib import Path

FORBIDDEN_SUFFIXES = {".zip", ".7z", ".rar", ".pdf", ".ppt", ".pptx", ".xls", ".xlsx"}
FORBIDDEN_PARTS = {"private", "private_dairy_anchor", "submission_package", "reviewer_material"}
SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"OPENAI_API_KEY\s*=\s*[^\s#]+"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
]
MAX_FILE_BYTES = 10 * 1024 * 1024


def scan(root: Path) -> list[str]:
    errors: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        lowered = {part.lower() for part in rel.parts}
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            errors.append(f"forbidden extension: {rel}")
        if lowered & FORBIDDEN_PARTS:
            errors.append(f"forbidden path segment: {rel}")
        if path.stat().st_size > MAX_FILE_BYTES:
            errors.append(f"file exceeds seed limit: {rel}")
        if path.suffix.lower() in {".md", ".txt", ".py", ".toml", ".json", ".yaml", ".yml", ".csv", ".cff"}:
            text = path.read_text(encoding="utf-8", errors="ignore")
            for pattern in SECRET_PATTERNS:
                if pattern.search(text) and path.name != ".env.example":
                    errors.append(f"possible secret: {rel}")
    return errors


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    errors = scan(root)
    if errors:
        print("Public release scan failed:")
        print("\n".join(f"- {e}" for e in errors))
        return 1
    print("Public release scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
