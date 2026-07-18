
# Testing Instructions

This file is finalized by TASK-058. During implementation, the minimum commands are:

```bash
python scripts/validate_seed.py
python -m pytest
python scripts/public_release_scan.py .
```

The final release must document clean installation, built-in scenario execution,
API-off fallback, API-on GPT stages, audit-bundle validation, and the public URL.
