"""Append-only, hash-chained audit log of analyst decisions (plan Sprint 7, human-in-the-loop).

One JSON object per line. Each entry stores ``prev_hash`` (the previous entry's ``entry_hash``;
64 zeros for the first entry) and its own ``entry_hash`` = SHA-256 of the canonical JSON of the
entry without ``entry_hash``. So an edited entry fails its own hash, and a deleted or reordered
entry breaks the chain at the next one. Deleting entries from the END cannot be seen from the
file alone: record the head hash elsewhere and pass it to ``verify(expect_head=...)``.

Only the ``triage approve`` CLI command writes here. Nothing in the AI path imports this module.

Limitations (see docs/approval.md): ``analyst`` is free text with no identity check; deleting
entries from the end is detected only with ``expect_head`` against a hash stored elsewhere; a
full rewrite with recomputed hashes is not detectable from the file alone.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

GENESIS = "0" * 64
DECISIONS = ("approve", "override", "escalate")
NOTE_REQUIRED = ("override", "escalate")


def _canonical(entry: dict) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


def read_entries(path: Path) -> list[dict]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def append_entry(
    path: Path,
    *,
    alert_id: str,
    decision: str,
    analyst: str,
    note: str | None,
    model: str | None,
    prompt_hash: str | None,
    run_ts: str | None,
    now: datetime | None = None,
) -> dict:
    """Validate and append one decision. Raises ValueError on invalid input; writes nothing then."""
    if decision not in DECISIONS:
        raise ValueError(f"decision must be one of {', '.join(DECISIONS)}")
    if not analyst or not analyst.strip():
        raise ValueError("analyst is required")
    note = (note or "").strip() or None
    if decision in NOTE_REQUIRED and not note:
        raise ValueError(f"a note is required for '{decision}'")
    entries = read_entries(path)
    entry = {
        "ts": (now or datetime.now(UTC)).isoformat(),
        "alert_id": alert_id,
        "decision": decision,
        "analyst": analyst.strip(),
        "note": note,
        "model": model,
        "prompt_hash": prompt_hash,
        "run_ts": run_ts,
        "prev_hash": entries[-1]["entry_hash"] if entries else GENESIS,
    }
    entry["entry_hash"] = entry_hash(entry)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(_canonical(entry) + "\n")
    return entry


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    head: str
    broken_at: int | None = None  # 1-based line number of the first broken entry
    reason: str | None = None


def verify(path: Path, expect_head: str | None = None) -> VerifyResult:
    try:
        entries = read_entries(path)
    except json.JSONDecodeError as exc:
        return VerifyResult(False, 0, "", exc.lineno, f"not valid JSON: {exc.msg}")
    prev = GENESIS
    for i, entry in enumerate(entries, start=1):
        if entry.get("prev_hash") != prev:
            return VerifyResult(False, len(entries), "", i,
                                "prev_hash does not match the previous entry "
                                "(an entry was deleted, inserted or reordered)")
        if entry.get("entry_hash") != entry_hash(entry):
            return VerifyResult(False, len(entries), "", i, "entry_hash mismatch (entry edited)")
        prev = entry["entry_hash"]
    if expect_head is not None and prev != expect_head:
        return VerifyResult(False, len(entries), prev, len(entries) or None,
                            "head hash differs from the expected head (entries removed from "
                            "the end, or appended)")
    return VerifyResult(True, len(entries), prev)


def latest_decision(path: Path, alert_id: str, run_ts: str | None) -> dict | None:
    """The most recent decision for this alert AND this triage run, or None."""
    found = None
    for entry in read_entries(path):
        if entry.get("alert_id") == alert_id and entry.get("run_ts") == run_ts:
            found = entry
    return found
