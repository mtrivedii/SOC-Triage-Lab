"""Which recorded runs belong to the published results, and where offline reports are written.

FROZEN_BEFORE: every run set reported in results/ was recorded before this instant. Live runs made
later (run records always carry a UTC ``ts``) are excluded, so a new run cannot change a published
table; report new runs with their own script and cutoff. Records without ``ts`` are the original
Sprint 5 injection runs (the runner added ``ts`` later) and are included.

TRIAGE_RESULTS_DIR: if set, reports are written there instead of results/ (``triage reproduce``
uses this to compare fresh output against the committed files). Inputs are always read from
results/.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "results"
FROZEN_BEFORE = datetime(2026, 10, 27, 18, 0, tzinfo=UTC)


def frozen(records: list[dict]) -> list[dict]:
    """Keep only records made before FROZEN_BEFORE (or without a timestamp)."""
    kept = []
    for rec in records:
        ts = rec.get("ts")
        if ts is None or datetime.fromisoformat(ts) < FROZEN_BEFORE:
            kept.append(rec)
    return kept


def out_path(name: str) -> Path:
    """Where an offline report named ``name`` is written."""
    base = Path(os.environ.get("TRIAGE_RESULTS_DIR") or RESULTS)
    base.mkdir(parents=True, exist_ok=True)
    return base / name
