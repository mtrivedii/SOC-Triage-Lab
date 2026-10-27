# Analyst approval and audit log

The AI output is a suggestion. An alert's report stays **DRAFT** until an analyst records a
decision with `triage approve`. Only that command writes to the audit log; the AI path never does.

```
uv run triage report <alert_id>                      # writes reports/<alert_id>.md (DRAFT until decided)
uv run triage approve <alert_id> --decision approve|override|escalate --analyst <name> [--note "..."]
uv run triage verify-audit [--expect-head <hash>]
```

- A note is required for `override` and `escalate`.
- A decision is bound to one triage run (its timestamp): by default the latest valid run for the
  alert, or `--run-ts` to pick one. A newer run of the same alert starts as DRAFT again.
- The default log is `audit/audit_log.jsonl` (git-ignored). `audit/audit_log.example.jsonl` is
  committed and holds only decisions made by the project owner.
- Each entry stores the UTC time, alert, decision, analyst, note, the triage run's model, prompt
  hash and timestamp, the previous entry's hash and its own hash (a SHA-256 hash chain).
- Reports re-run the grounding checker v2 on the full alert and list its flags at the top: hard
  flags (unsupported IDs, quotes, IPs or numbers) first, then the lower-severity
  `evidence_only_numbers` (numbers that appear only in the untrusted evidence lines).

## Limitations

- **`--analyst` is free text.** There is no login or identity check. Anyone who can run the
  command can record a decision under any name. The log shows what was recorded, not who
  recorded it.
- **Tail deletion is only detected against an external anchor.** Edits, deletions in the middle,
  insertions and reordering break the hash chain and are reported by `verify-audit`. Removing
  entries from the END leaves a valid shorter chain. It is detected only with
  `verify-audit --expect-head <hash>`, using a head hash stored somewhere else (e.g. a ticket or
  a signed note). The log itself does not do this.
- **No protection against rewriting the whole file.** Someone with write access can recompute
  every hash. The chain shows accidental or partial edits, not a full rewrite; that needs the
  external head hash above or append-only storage.
- **A broken log means no trusted decision.** If `verify-audit` fails, every report shows DRAFT.
