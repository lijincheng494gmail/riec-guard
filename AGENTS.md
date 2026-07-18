# RIEC Guard Public Repository Instructions

This repository is the only writable code root for Build Week development.

## Boundaries
- Never read or copy files from parent `PRIVATE_LOCAL_REFERENCE`, historical ZIP/PDF/PPTX/XLSX files, or private dairy paths.
- Keep public synthetic data and private/local adapters physically separate.
- Do not commit `.env`, secrets, uploads, run directories, caches, databases, or generated private/mixed outputs.
- Preserve the frozen candidate library, grouped deployment semantics, six action states, evidence IDs, and claim boundaries unless the current task explicitly implements their already-defined specification.

## Engineering expectations
- Python 3.12 target; typed public interfaces and deterministic seeds.
- Run the exact tests named by the current task plus focused regression tests.
- Keep GPT-facing logic separate from deterministic statistics.
- Use the Responses API with `gpt-5.6-sol`, structured outputs/function tools as specified, and `store=false`.
- A GPT outage must produce an honest fallback state; it must never be represented as a successful GPT run.
- Do not start a second task in the same turn.

## Core quality commands
The final commands are pinned by TASK-002. Until then, use the seed checks in `Makefile` and the current task contract.
