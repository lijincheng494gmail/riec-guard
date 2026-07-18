
.PHONY: seed-check test release-scan task-note

seed-check:
	python scripts/validate_seed.py

test:
	python -m pytest

release-scan:
	python scripts/public_release_scan.py .

task-note:
	@echo "Open the Phase E command pack and execute only the next unblocked task."
